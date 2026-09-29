"""
Multi-threaded DPI Engine.

Architecture::

    Reader (main thread) ──┬──► LB0 ──┬──► FP0 ──┐
                           │          └──► FP1 ──┤
                           └──► LB1 ──┬──► FP2 ──┼──► Output Queue ──► Writer ──► PCAP
                                      └──► FP3 ──┘
                            (unsupported / malformed packets go straight to the output queue)

Lifecycle
---------
1. The reader assigns every packet a contiguous ``packet_id`` in file order and
   acquires one permit from a bounded *window* semaphore before admitting it.
   Supported packets are dispatched to a load balancer; unsupported/malformed
   packets are sent straight to the writer as completions.  When the window is
   full the reader blocks -- this is the only backpressure mechanism and it
   bounds every queue and the writer's reorder buffer.
2. At end of input the reader sends one ``_END`` sentinel to every LB.  Each LB
   forwards ``_END`` to every FP it owns and exits.  Each FP emits a ``_Done``
   marker on the output queue and exits.  Queues are FIFO, so a marker is
   always behind every completion that stage produced.
3. The writer reorders completions by ``packet_id`` and retires them in input
   order, releasing one window permit per retired packet.  Filtered,
   unsupported and malformed packets produce completions too, so the sequence
   of ids is contiguous and the writer never waits for an id that will not
   arrive.  It finishes when it has seen a ``_Done`` from every FP.
4. The main thread joins every thread (no fixed sleeps), verifies that the
   accounting reconciles, and only then moves the ``.partial`` output into
   place.  Any worker exception, cancellation, or reconciliation failure
   discards the partial output and raises ``ProcessingError``.

Every blocking queue/semaphore operation polls a shared stop event, so a
failure in any stage -- even with every queue full -- unwinds all the others.

Routing
-------
``flow_hash`` hashes the *canonical* five-tuple (endpoints sorted), so both
directions of a connection reach the same FP (bidirectional affinity).  The
LB index is ``h % num_lbs`` and the FP index within that LB is
``(h // num_lbs) % fps_per_lb``; using the quotient makes the second choice
independent of the first, so every FP is reachable.  Flow *state* remains
directional (see ``dpi.inspection.FlowProcessor``) to match the simple engine.
"""

from __future__ import annotations

import heapq
import queue
import struct
import sys
import threading
import time
import zlib
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, Dict, Iterator, List, Optional, Tuple

# Ensure UTF-8 output on Windows (box-drawing characters)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from dpi.types import (
    AppType,
    Connection,
    DPIStats,
    FiveTuple,
    FlowCapacity,
    PacketJob,
    ProcessingCancelled,
    ProcessingError,
    ip_to_str,
)
from dpi.pcap_io import PcapReader, PcapWriter
from dpi.packet_parser import PacketParser, PROTO_TCP
from dpi.rule_manager import RuleManager
from dpi.inspection import DetectionLog, FlowProcessor, Outcome, categorize, make_tuple


_POLL_INTERVAL = 0.05   # seconds between stop-event checks while blocked
_END = object()         # end-of-input sentinel for LB / FP input queues

InspectHook = Callable[[int, PacketJob], None]


# =============================================================================
# Routing
# =============================================================================

def flow_hash(t: FiveTuple) -> int:
    """Stable 32-bit hash of the canonical (direction-independent) five-tuple."""
    a = (t.src_ip, t.src_port)
    b = (t.dst_ip, t.dst_port)
    lo, hi = (a, b) if a <= b else (b, a)
    return zlib.crc32(struct.pack("!IHIHB", lo[0], lo[1], hi[0], hi[1], t.protocol & 0xFF))


def route(t: FiveTuple, num_lbs: int, fps_per_lb: int) -> Tuple[int, int]:
    """Return ``(lb_index, fp_index_within_lb)`` for a flow."""
    h = flow_hash(t)
    return h % num_lbs, (h // num_lbs) % fps_per_lb


# =============================================================================
# Shared control plane
# =============================================================================

class _Cancelled(Exception):
    """Raised inside a stage when the pipeline is stopping."""


class _Control:
    """Stop flag + error list shared by every stage; makes blocking ops interruptible."""

    def __init__(self) -> None:
        self.stop = threading.Event()
        self._lock = threading.Lock()
        self.errors: List[Tuple[str, BaseException]] = []
        self.cancelled = False

    def fail(self, stage: str, exc: BaseException) -> None:
        with self._lock:
            self.errors.append((stage, exc))
        self.stop.set()

    def cancel(self) -> None:
        self.cancelled = True
        self.stop.set()

    def put(self, q: "queue.Queue", item: object) -> None:
        while True:
            if self.stop.is_set():
                raise _Cancelled()
            try:
                q.put(item, timeout=_POLL_INTERVAL)
                return
            except queue.Full:
                continue

    def get(self, q: "queue.Queue") -> object:
        while True:
            if self.stop.is_set():
                raise _Cancelled()
            try:
                return q.get(timeout=_POLL_INTERVAL)
            except queue.Empty:
                continue

    def acquire(self, sem: threading.Semaphore) -> None:
        while True:
            if self.stop.is_set():
                raise _Cancelled()
            if sem.acquire(timeout=_POLL_INTERVAL):
                return


class _Stage:
    """Base class: runs ``_loop`` in a thread and routes failures to the control plane."""

    name = "stage"

    def __init__(self, ctrl: _Control) -> None:
        self._ctrl = ctrl
        self._thread: Optional[threading.Thread] = None
        self.finished = False

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name=self.name, daemon=True)
        self._thread.start()

    def join(self, timeout: Optional[float]) -> bool:
        if self._thread is None:
            return True
        self._thread.join(timeout)
        return not self._thread.is_alive()

    def _run(self) -> None:
        try:
            self._loop()
            self.finished = True
        except _Cancelled:
            pass
        except BaseException as exc:  # noqa: BLE001 - every worker error must be surfaced
            self._ctrl.fail(self.name, exc)

    def _loop(self) -> None:
        raise NotImplementedError


# =============================================================================
# Messages on the output queue
# =============================================================================

@dataclass
class _Completion:
    packet_id: int
    outcome: Outcome
    job: Optional[PacketJob] = None   # present only for RETAINED


class _Done:
    __slots__ = ("fp_id",)

    def __init__(self, fp_id: int) -> None:
        self.fp_id = fp_id


# =============================================================================
# Fast Path (one per FP thread)
# =============================================================================

class _FastPath(_Stage):
    """Inspects packets, tracks flows, and emits a completion for every job."""

    def __init__(
        self,
        fp_id: int,
        rules: RuleManager,
        ctrl: _Control,
        output_queue: "queue.Queue",
        queue_size: int,
        inspect_hook: Optional[InspectHook],
        capacity: FlowCapacity,
        detail_limit: int,
    ) -> None:
        super().__init__(ctrl)
        self.id = fp_id
        self.name = f"FP-{fp_id}"
        self.input_queue: "queue.Queue" = queue.Queue(maxsize=queue_size)
        self._output_queue = output_queue
        self._processor = FlowProcessor(rules, capacity=capacity)
        self._hook = inspect_hook
        self._detail_limit = detail_limit
        self.processed = 0            # decisions made by this FP (single writer: this thread)
        self.app_stats: Dict[AppType, int] = defaultdict(int)
        # Bounded report detail: at most ``detail_limit`` entries each; the rest are counted.
        self.detections: List[Tuple[int, str, AppType]] = []          # (packet_id, name, app)
        self.detections_dropped = 0
        self.blocked_flows: List[Tuple[int, FiveTuple, AppType, str]] = []
        self.blocked_dropped = 0

    @property
    def flow_count(self) -> int:
        return self._processor.tracker.active_count

    def connections(self) -> Iterator[Connection]:
        return self._processor.tracker.iter_connections()

    def _loop(self) -> None:
        while True:
            job = self._ctrl.get(self.input_queue)
            if job is _END:
                self._ctrl.put(self._output_queue, _Done(self.id))
                return

            if self._hook is not None:
                self._hook(self.id, job)

            payload = (job.data[job.payload_offset: job.payload_offset + job.payload_length]
                       if job.payload_length > 0 else b"")
            decision = self._processor.process(
                job.tuple, job.tuple.protocol == PROTO_TCP, payload, len(job.data), job.packet_id,
            )
            self.processed += 1
            self.app_stats[decision.conn.app_type] += 1
            if decision.detected:
                if len(self.detections) < self._detail_limit:
                    self.detections.append((job.packet_id, decision.detected[0], decision.detected[1]))
                else:
                    self.detections_dropped += 1
            if decision.newly_blocked:
                if len(self.blocked_flows) < self._detail_limit:
                    self.blocked_flows.append((job.packet_id, job.tuple, decision.conn.app_type, decision.conn.sni))
                else:
                    self.blocked_dropped += 1

            self._ctrl.put(
                self._output_queue,
                _Completion(job.packet_id, decision.outcome, None if decision.blocked else job),
            )


# =============================================================================
# Load Balancer (one per LB thread)
# =============================================================================

class _LoadBalancer(_Stage):
    """Dispatches jobs to its FPs by flow hash; propagates end-of-input to each of them."""

    def __init__(self, lb_id: int, fps: List[_FastPath], num_lbs: int, ctrl: _Control, queue_size: int) -> None:
        super().__init__(ctrl)
        self.id = lb_id
        self.name = f"LB-{lb_id}"
        self._fps = fps
        self._num_lbs = num_lbs
        self._fps_per_lb = len(fps)
        self.input_queue: "queue.Queue" = queue.Queue(maxsize=queue_size)
        self.dispatched = 0

    def _loop(self) -> None:
        while True:
            job = self._ctrl.get(self.input_queue)
            if job is _END:
                for fp in self._fps:
                    self._ctrl.put(fp.input_queue, _END)
                return
            _, fp_idx = route(job.tuple, self._num_lbs, self._fps_per_lb)
            self._ctrl.put(self._fps[fp_idx].input_queue, job)
            self.dispatched += 1


# =============================================================================
# Writer
# =============================================================================

class _Writer(_Stage):
    """Retires completions in packet-id order; writes retained packets; owns outcome stats."""

    name = "Writer"

    def __init__(
        self,
        ctrl: _Control,
        output_queue: "queue.Queue",
        pcap_writer: PcapWriter,
        stats: DPIStats,
        total_fps: int,
        window: threading.Semaphore,
    ) -> None:
        super().__init__(ctrl)
        self._output_queue = output_queue
        self._pcap = pcap_writer
        self._stats = stats
        self._total_fps = total_fps
        self._window = window
        self.next_id = 0
        self.pending: Dict[int, _Completion] = {}
        self.max_pending = 0

    def _loop(self) -> None:
        fps_done = 0
        while fps_done < self._total_fps:
            item = self._ctrl.get(self._output_queue)
            if isinstance(item, _Done):
                fps_done += 1
                continue
            self.pending[item.packet_id] = item
            if len(self.pending) > self.max_pending:
                self.max_pending = len(self.pending)
            self._flush()
        self._flush()
        if self.pending:
            raise RuntimeError(
                f"{len(self.pending)} completion(s) left unordered: expected packet id "
                f"{self.next_id}, lowest pending id {min(self.pending)}"
            )

    def _flush(self) -> None:
        while self.next_id in self.pending:
            c = self.pending.pop(self.next_id)
            if c.outcome is Outcome.RETAINED:
                self._pcap.write_packet(c.job.ts_sec, c.job.ts_usec, c.job.data, c.job.orig_len)
                self._stats.forwarded_packets += 1
            elif c.outcome is Outcome.FILTERED:
                self._stats.dropped_packets += 1
            elif c.outcome is Outcome.UNSUPPORTED:
                self._stats.unsupported_packets += 1
            elif c.outcome is Outcome.MALFORMED:
                self._stats.malformed_packets += 1
            else:
                raise RuntimeError(f"unexpected outcome {c.outcome!r} for packet {c.packet_id}")
            self.next_id += 1
            self._window.release()


# =============================================================================
# Multi-Threaded DPI Engine
# =============================================================================

class DPIEngineMT:
    """
    Multi-threaded Deep Packet Inspection engine.

    Usage::

        engine = DPIEngineMT(num_lbs=2, fps_per_lb=2)
        engine.rule_manager.block_app("YouTube")
        engine.process_file("input.pcap", "output.pcap")

    ``process_file`` raises ``ProcessingError`` (or ``ProcessingCancelled``)
    if the output could not be produced completely; in that case no file is
    left at the output path.  An engine instance is meant for a single run.

    ``queue_size`` bounds the number of packets in flight between the reader
    and the writer (and therefore the reorder buffer and every stage queue).

    ``inspect_hook(fp_id, job)`` is an instrumentation hook called by each FP
    thread before it inspects a packet; it exists for deterministic testing.
    """

    def __init__(
        self,
        num_lbs: int = 2,
        fps_per_lb: int = 2,
        queue_size: int = 10_000,
        inspect_hook: Optional[InspectHook] = None,
        join_timeout: float = 60.0,
        max_flows: int = FlowCapacity.DEFAULT_MAX_FLOWS,
        max_report_detail: int = DetectionLog.DEFAULT_LIMIT,
    ) -> None:
        if num_lbs < 1 or fps_per_lb < 1:
            raise ValueError("num_lbs and fps_per_lb must be >= 1")
        if queue_size < 1:
            raise ValueError("queue_size must be >= 1")
        if max_report_detail < 0:
            raise ValueError("max_report_detail must be >= 0")

        self.num_lbs = num_lbs
        self.fps_per_lb = fps_per_lb
        self.total_fps = num_lbs * fps_per_lb
        self.queue_size = queue_size
        self.max_report_detail = max_report_detail
        self._join_timeout = join_timeout

        self.rule_manager = RuleManager()
        self.stats = DPIStats()
        self.flow_capacity = FlowCapacity(max_flows)

        self._app_stats: Dict[AppType, int] = defaultdict(int)
        self._detections = DetectionLog(max_report_detail)
        self._blocked_flows: List[Tuple[FiveTuple, AppType, str]] = []
        self._blocked_dropped = 0
        self.abort_summary: Dict[str, object] = {}

        self._ctrl = _Control()
        self._window = threading.BoundedSemaphore(queue_size)
        self._output_queue: "queue.Queue" = queue.Queue(maxsize=queue_size + self.total_fps)
        self.reader_finished = threading.Event()

        self._fps: List[_FastPath] = [
            _FastPath(i, self.rule_manager, self._ctrl, self._output_queue, queue_size, inspect_hook,
                      self.flow_capacity, max_report_detail)
            for i in range(self.total_fps)
        ]
        self._lbs: List[_LoadBalancer] = [
            _LoadBalancer(
                lb_id,
                self._fps[lb_id * fps_per_lb:(lb_id + 1) * fps_per_lb],
                num_lbs, self._ctrl, queue_size,
            )
            for lb_id in range(num_lbs)
        ]
        self._writer: Optional[_Writer] = None
        self._run_total = 0            # admitted this run (reader thread only)
        self._reader_decided = 0       # unsupported/malformed decided by the reader
        self._committed = False

    @property
    def _detected_snis(self) -> Dict[str, AppType]:
        return self._detections.items

    @property
    def detections(self) -> DetectionLog:
        return self._detections

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------

    def block_ip(self, ip: str) -> None:
        self.rule_manager.block_ip(ip)

    def block_app(self, app: str) -> None:
        self.rule_manager.block_app(app)

    def block_domain(self, domain: str) -> None:
        self.rule_manager.block_domain(domain)

    def block_port(self, port: int) -> None:
        self.rule_manager.block_port(port)

    def load_rules(self, filename: str) -> bool:
        return self.rule_manager.load_rules(filename)

    def cancel(self) -> None:
        """Request that a running ``process_file`` stop as soon as possible."""
        self._ctrl.cancel()

    @property
    def stopping(self) -> threading.Event:
        """Set once the pipeline is shutting down (failure or cancellation)."""
        return self._ctrl.stop

    @property
    def errors(self) -> List[Tuple[str, BaseException]]:
        return list(self._ctrl.errors)

    @property
    def mode(self) -> str:
        return "mt"

    @property
    def app_stats(self) -> Dict[AppType, int]:
        """Per-packet heuristic class counts (merged after the run)."""
        return dict(self._app_stats)

    def connections(self) -> Iterator[Connection]:
        """All tracked flows across fast paths (unordered; see ``connections_sorted``)."""
        for fp in self._fps:
            yield from fp.connections()

    def connections_sorted(self, limit: Optional[int] = None) -> List[Connection]:
        """
        Flows in first-seen packet order.  With ``limit`` only the first
        ``limit`` flows are materialised (a bounded heap), so building a capped
        report never allocates a list of every flow.
        """
        key = lambda c: c.first_packet_id
        if limit is None:
            return sorted(self.connections(), key=key)
        return heapq.nsmallest(limit, self.connections(), key=key)

    @property
    def flow_count(self) -> int:
        return sum(fp.flow_count for fp in self._fps)

    def process_file(self, input_path: str, output_path: str) -> None:
        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║              DPI ENGINE v2.0 (Multi-threaded)               ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Load Balancers: {self.num_lbs:>2}    FPs per LB: {self.fps_per_lb:>2}"
              f"    Total FPs: {self.total_fps:>2}     ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print()

        if self._ctrl.stop.is_set():
            raise ProcessingCancelled("engine was cancelled before processing started")

        reader = PcapReader()
        pcap_writer = PcapWriter()
        stages: List[_Stage] = []
        self._committed = False
        try:
            # --- startup -------------------------------------------------------
            if not reader.open(input_path):
                raise ProcessingError(f"could not open input PCAP: {input_path}: {reader.last_error}")
            if not pcap_writer.open(output_path, global_header=reader.global_header, atomic=True):
                raise ProcessingError(f"could not open output PCAP: {output_path}: {pcap_writer.last_error}")

            self._writer = _Writer(
                self._ctrl, self._output_queue, pcap_writer, self.stats, self.total_fps, self._window,
            )
            stages = [*self._fps, *self._lbs, self._writer]
            for stage in stages:
                stage.start()

            # --- read / dispatch / signal end of input ---------------------------
            print("[Reader] Processing packets...")
            try:
                self._read_and_dispatch(reader)
                self.reader_finished.set()
                for lb in self._lbs:
                    self._ctrl.put(lb.input_queue, _END)
            except _Cancelled:
                pass
            except KeyboardInterrupt:
                self._ctrl.cancel()
            except BaseException as exc:  # noqa: BLE001
                self._ctrl.fail("Reader", exc)

            # --- join / finalize ------------------------------------------------
            self._join_all(stages)
            self._finish(pcap_writer, output_path)

        except KeyboardInterrupt:
            # Interrupt anywhere outside the read loop (startup, join, finalize):
            # cancel, unblock and join every stage, close and clean up, then
            # report cancellation -- unless the output was already committed.
            if self._committed:
                print("\n[Engine] interrupted after the output was committed; output is complete")
                return
            self._ctrl.cancel()
            problems = self._emergency_shutdown(stages, pcap_writer)
            self._record_abort()
            raise ProcessingCancelled(
                self._abort_message("processing cancelled (interrupted)", problems)
            ) from None
        finally:
            reader.close()

    # -----------------------------------------------------------------
    # Internals
    # -----------------------------------------------------------------

    def _read_and_dispatch(self, reader: PcapReader) -> None:
        self._run_total = 0
        self._reader_decided = 0
        for raw in reader:
            pkt_id = self._run_total
            self._ctrl.acquire(self._window)
            self._run_total += 1
            self.stats.total_packets += 1
            self.stats.total_bytes += len(raw.data)

            parsed = PacketParser.parse(raw.data, ts_sec=raw.header.ts_sec, ts_usec=raw.header.ts_usec)
            skip = categorize(parsed)
            if skip is not None:
                self._reader_decided += 1
                self._ctrl.put(self._output_queue, _Completion(pkt_id, skip))
                continue

            if parsed.has_tcp:
                self.stats.tcp_packets += 1
            else:
                self.stats.udp_packets += 1

            job = PacketJob(
                packet_id=pkt_id,
                tuple=make_tuple(parsed),
                data=raw.data,
                tcp_flags=parsed.tcp_flags,
                payload_offset=parsed.payload_offset,
                payload_length=parsed.payload_length,
                ts_sec=raw.header.ts_sec,
                ts_usec=raw.header.ts_usec,
                orig_len=raw.header.orig_len,
            )
            lb_idx, _ = route(job.tuple, self.num_lbs, self.fps_per_lb)
            self._ctrl.put(self._lbs[lb_idx].input_queue, job)

        print(f"[Reader] Done reading {self._run_total} packets")

    def _join_all(self, stages: List[_Stage]) -> None:
        """
        Join every stage, polling in short slices so a pending KeyboardInterrupt
        is delivered between polls (a single long ``join`` cannot be interrupted
        on Windows).  A stage that does not stop within ``join_timeout`` is
        recorded as a failure; the run then cannot succeed.
        """
        deadline = time.monotonic() + self._join_timeout
        for stage in stages:
            while not stage.join(_POLL_INTERVAL * 2):
                if time.monotonic() >= deadline:
                    self._ctrl.fail(stage.name, RuntimeError(
                        f"{stage.name} did not stop within {self._join_timeout}s"))
                    break
        # A second pass gives stragglers a chance to observe a stop flag set above.
        for stage in stages:
            stage.join(_POLL_INTERVAL * 4)

    def _emergency_shutdown(self, stages: List[_Stage], pcap_writer: PcapWriter) -> List[str]:
        """
        Cancellation path used after an interrupt: join all stages (tolerating
        repeated interrupts), discard the temporary output, and return a list
        of problems (threads still alive, files left behind).  Never raises.
        """
        problems: List[str] = []
        for attempt in range(3):
            try:
                self._join_all(stages)
                break
            except KeyboardInterrupt:
                self._ctrl.cancel()
                if attempt == 2:
                    problems.append("repeated interrupts while waiting for stages")
        alive = [s.name for s in stages if s._thread is not None and s._thread.is_alive()]
        if alive:
            problems.append("stage(s) still running: " + ", ".join(alive))
        try:
            leftover = pcap_writer.discard()
            if leftover:
                problems.append(leftover)
        except BaseException as e:  # noqa: BLE001 -- cleanup must not mask the cancellation
            problems.append(f"cleanup failed: {type(e).__name__}: {e}")
        return problems

    def _record_abort(self) -> None:
        """
        Aborted-run accounting.

        admitted           packets read from the input and assigned an id this run
        decided            admitted packets whose outcome was determined (reader
                           skips + fast-path decisions); a decision may still be
                           waiting in the reorder buffer
        retired            decided packets the writer processed in order (these
                           are the ones counted in the terminal categories)
        decided_unretired  decided - retired
        undecided          admitted - decided (queued or in progress when stopped)
        input_fully_read   whether the reader reached end of input; how many
                           packets remain unread is unknown otherwise

        ``stats.failed_packets`` = admitted - retired: every admitted packet not
        represented in the output.  ``stats.reconciles()`` then holds.
        """
        s = self.stats
        writer = self._writer
        retired = writer.next_id if writer is not None else 0
        decided = self._reader_decided + sum(fp.processed for fp in self._fps)
        admitted = self._run_total
        s.failed_packets = admitted - retired
        self.abort_summary = {
            "admitted": admitted,
            "decided": decided,
            "retired": retired,
            "decided_unretired": max(0, decided - retired),
            "undecided": max(0, admitted - decided),
            "input_fully_read": self.reader_finished.is_set(),
            "cancelled": self._ctrl.cancelled,
            "errors": [f"{stage}: {type(e).__name__}: {e}" for stage, e in self._ctrl.errors],
        }

    def _abort_message(self, reason: str, problems: List[str]) -> str:
        a = self.abort_summary
        read = "input fully read" if a["input_fully_read"] else "input not fully read; unread count unknown"
        msg = (f"{reason}; admitted {a['admitted']} packet(s) ({read}), {a['decided']} decided, "
               f"{a['retired']} retired, {a['decided_unretired']} decided but not yet retired, "
               f"{a['undecided']} undecided; output discarded")
        if problems:
            msg += "; " + "; ".join(problems)
        return msg

    def _finish(self, pcap_writer: PcapWriter, output_path: str) -> None:
        stats = self.stats
        writer = self._writer
        failed = self._ctrl.stop.is_set() or bool(self._ctrl.errors) or writer is None or not writer.finished

        if not failed and (writer.next_id != self._run_total or not stats.reconciles()):
            self._ctrl.fail("Engine", RuntimeError(
                f"accounting mismatch: read {self._run_total}, retired {writer.next_id}, "
                f"total {stats.total_packets}, accounted {stats.accounted_packets}"
            ))
            failed = True

        if failed:
            problems: List[str] = []
            leftover = pcap_writer.discard()
            if leftover:
                problems.append(leftover)
            self._record_abort()
            self._merge_worker_stats()
            if self._ctrl.errors:
                stage, exc = self._ctrl.errors[0]
                detail = "; ".join(f"{s}: {type(e).__name__}: {e}" for s, e in self._ctrl.errors)
                # Keep the specific ProcessingError subclass (e.g. FlowCapacityExceeded,
                # PcapFormatError) so both engines fail with the same exception type.
                err_type = type(exc) if isinstance(exc, ProcessingError) else ProcessingError
                raise err_type(self._abort_message(f"processing failed ({detail})", problems)) from exc
            raise ProcessingCancelled(self._abort_message("processing cancelled", problems))

        pcap_writer.commit()          # PcapWriteError on failure; temp handled by the writer
        self._committed = True
        self._merge_worker_stats()
        self._print_report(output_path)

    def _merge_worker_stats(self) -> None:
        """
        Merge per-FP results in packet order so reports match the single-threaded
        engine.  Detail lists are bounded by ``max_report_detail``: each FP kept
        at most that many entries, and the merged result keeps the first
        ``max_report_detail`` by packet id; everything else is counted.
        """
        limit = self.max_report_detail
        self._app_stats.clear()
        self._detections = DetectionLog(limit)
        self._blocked_flows = []
        detections: List[Tuple[int, str, AppType]] = []
        blocked: List[Tuple[int, FiveTuple, AppType, str]] = []
        dropped_det = dropped_blk = 0
        for fp in self._fps:
            for app, n in fp.app_stats.items():
                self._app_stats[app] += n
            detections.extend(fp.detections)
            blocked.extend(fp.blocked_flows)
            dropped_det += fp.detections_dropped
            dropped_blk += fp.blocked_dropped
        detections.sort(key=lambda d: d[0])
        for _, name, app in detections:
            self._detections.add(name, app)
        self._detections.dropped += dropped_det
        self._detections.total += dropped_det
        blocked.sort(key=lambda b: b[0])
        self._blocked_flows = [b[1:] for b in blocked[:limit]]
        self._blocked_dropped = dropped_blk + max(0, len(blocked) - limit)
        self.stats.active_connections = self.flow_count

    # -----------------------------------------------------------------
    # Report
    # -----------------------------------------------------------------

    def _print_report(self, output_path: str) -> None:
        stats = self.stats
        total = stats.total_packets

        for tuple_, app, sni in self._blocked_flows:
            print(f"[BLOCKED] {ip_to_str(tuple_.src_ip)} -> {ip_to_str(tuple_.dst_ip)}"
                  f" ({app.value}{': ' + sni if sni else ''})")
        if self._blocked_dropped:
            print(f"[BLOCKED] ... {self._blocked_dropped} further blocked flow(s) not listed "
                  f"(limit {self.max_report_detail}, see --max-report-detail)")

        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                      PROCESSING REPORT                     ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Total Packets:      {total:>12}                         ║")
        print(f"║ Total Bytes:        {stats.total_bytes:>12}                         ║")
        print(f"║ TCP Packets:        {stats.tcp_packets:>12}                         ║")
        print(f"║ UDP Packets:        {stats.udp_packets:>12}                         ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Retained (written): {stats.forwarded_packets:>12}                         ║")
        print(f"║ Rule-filtered:      {stats.dropped_packets:>12}                         ║")
        print(f"║ Unsupported:        {stats.unsupported_packets:>12}                         ║")
        print(f"║ Malformed:          {stats.malformed_packets:>12}                         ║")
        print(f"║ Active Flows:       {stats.active_connections:>12}                         ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║ THREAD STATISTICS                                          ║")
        for lb in self._lbs:
            print(f"║   LB{lb.id} dispatched:   {lb.dispatched:>12}                         ║")
        for fp in self._fps:
            print(f"║   FP{fp.id} processed:    {fp.processed:>12}                         ║")
        if self._writer is not None:
            print(f"║   Writer max reorder buffer: {self._writer.max_pending:>8}                    ║")

        print("╠══════════════════════════════════════════════════════════════╣")
        print("║                   APPLICATION BREAKDOWN                    ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        sorted_apps = sorted(self._app_stats.items(), key=lambda x: x[1], reverse=True)
        for app, count in sorted_apps:
            pct = (100.0 * count / total) if total > 0 else 0
            bar = "#" * int(pct / 5)
            print(f"║ {app.value:<15} {count:>8} {pct:>5.1f}% {bar:<20}  ║")
        print("╚══════════════════════════════════════════════════════════════╝")

        if self._detected_snis:
            print("\n[Detected Domains/SNIs]")
            for sni, app in self._detected_snis.items():
                print(f"  - {sni} -> {app.value}")
            if self._detections.truncated:
                print(f"  ... {self._detections.dropped} further detection(s) not listed "
                      f"(limit {self._detections.limit}, see --max-report-detail)")

        if stats.unsupported_packets or stats.malformed_packets:
            print(f"\nNote: {stats.unsupported_packets} unsupported and {stats.malformed_packets} malformed "
                  f"packet(s) were not inspected and are not in the output.")
        print(f"\nOutput written to: {output_path}")
