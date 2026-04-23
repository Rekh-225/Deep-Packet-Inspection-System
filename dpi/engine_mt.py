"""
Multi-threaded DPI Engine.

Architecture::

    Reader Thread ──┬──► LB0 ──┬──► FP0
                    │          └──► FP1
                    └──► LB1 ──┬──► FP2
                               └──► FP3
                                     │
                                     ▼
                              Output Queue ──► Writer Thread

Each component runs in its own ``threading.Thread``.  Consistent hashing
on the five-tuple ensures all packets of the same flow land on the same
Fast Path thread, enabling correct per-flow state tracking.
"""

from __future__ import annotations

import queue
import struct
import sys
import threading
from collections import defaultdict
from typing import Optional

# Ensure UTF-8 output on Windows (box-drawing characters)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from dpi.types import (
    AppType,
    Connection,
    ConnectionState,
    DPIStats,
    FiveTuple,
    PacketAction,
    PacketJob,
    ip_to_str,
    sni_to_app_type,
    str_to_ip,
)
from dpi.pcap_io import PcapReader, PcapWriter, PcapPacketHeader
from dpi.packet_parser import PacketParser, ParsedPacket
from dpi.sni_extractor import SNIExtractor, HTTPHostExtractor, DNSExtractor
from dpi.rule_manager import RuleManager


# Sentinel value to signal thread shutdown
_SENTINEL = None
_QUEUE_TIMEOUT = 0.1  # seconds


# =============================================================================
# Fast Path Processor (one per FP thread)
# =============================================================================

class _FastPath:
    """Inspects packets, tracks flows, and makes forward/drop decisions."""

    def __init__(
        self,
        fp_id: int,
        rules: RuleManager,
        stats: DPIStats,
        app_stats: dict,
        app_lock: threading.Lock,
        sni_map: dict,
        output_queue: queue.Queue,
    ) -> None:
        self.id = fp_id
        self._rules = rules
        self._stats = stats
        self._app_stats = app_stats
        self._app_lock = app_lock
        self._sni_map = sni_map
        self._output_queue = output_queue
        self.input_queue: queue.Queue[Optional[PacketJob]] = queue.Queue(maxsize=10_000)
        self._flows: dict[FiveTuple, _FlowEntry] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.processed = 0

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._run, name=f"FP-{self.id}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self.input_queue.put(_SENTINEL)
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self) -> None:
        while self._running:
            try:
                job = self.input_queue.get(timeout=_QUEUE_TIMEOUT)
            except queue.Empty:
                continue
            if job is _SENTINEL:
                break

            self.processed += 1

            # Get or create flow
            flow = self._flows.get(job.tuple)
            if flow is None:
                flow = _FlowEntry(tuple=job.tuple)
                self._flows[job.tuple] = flow
            flow.packets += 1
            flow.bytes += len(job.data)

            # Classify
            if not flow.classified:
                self._classify(job, flow)

            # Check blocking
            if not flow.blocked:
                flow.blocked = bool(self._rules.should_block(
                    job.tuple.src_ip, job.tuple.dst_port, flow.app_type, flow.sni,
                ))

            # Record app stats
            with self._app_lock:
                self._app_stats[flow.app_type] = self._app_stats.get(flow.app_type, 0) + 1
                if flow.sni:
                    self._sni_map[flow.sni] = flow.app_type

            # Forward or drop
            if flow.blocked:
                self._stats.dropped_packets += 1
            else:
                self._stats.forwarded_packets += 1
                self._output_queue.put(job)

    def _classify(self, job: PacketJob, flow: _FlowEntry) -> None:
        payload = job.data[job.payload_offset:] if job.payload_length > 0 else b""

        # TLS SNI
        if job.tuple.dst_port == 443 and len(payload) > 5:
            sni = SNIExtractor.extract(payload)
            if sni:
                flow.sni = sni
                flow.app_type = sni_to_app_type(sni)
                flow.classified = True
                return

        # HTTP Host
        if job.tuple.dst_port == 80 and len(payload) > 10:
            host = HTTPHostExtractor.extract(payload)
            if host:
                flow.sni = host
                flow.app_type = sni_to_app_type(host)
                flow.classified = True
                return

        # DNS
        if job.tuple.dst_port == 53 or job.tuple.src_port == 53:
            flow.app_type = AppType.DNS
            flow.classified = True
            return

        # Port-based fallback
        if job.tuple.dst_port == 443:
            flow.app_type = AppType.HTTPS
        elif job.tuple.dst_port == 80:
            flow.app_type = AppType.HTTP


class _FlowEntry:
    __slots__ = ("tuple", "app_type", "sni", "packets", "bytes", "blocked", "classified")

    def __init__(self, tuple: FiveTuple):
        self.tuple = tuple
        self.app_type: AppType = AppType.UNKNOWN
        self.sni: str = ""
        self.packets: int = 0
        self.bytes: int = 0
        self.blocked: bool = False
        self.classified: bool = False


# =============================================================================
# Load Balancer (one per LB thread)
# =============================================================================

class _LoadBalancer:
    """Receives packets and dispatches them to FP threads via consistent hashing."""

    def __init__(self, lb_id: int, fps: list[_FastPath]) -> None:
        self.id = lb_id
        self._fps = fps
        self._num_fps = len(fps)
        self.input_queue: queue.Queue[Optional[PacketJob]] = queue.Queue(maxsize=10_000)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.dispatched = 0

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._run, name=f"LB-{self.id}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self.input_queue.put(_SENTINEL)
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self) -> None:
        while self._running:
            try:
                job = self.input_queue.get(timeout=_QUEUE_TIMEOUT)
            except queue.Empty:
                continue
            if job is _SENTINEL:
                break

            fp_idx = hash(job.tuple) % self._num_fps
            self._fps[fp_idx].input_queue.put(job)
            self.dispatched += 1


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
    """

    def __init__(self, num_lbs: int = 2, fps_per_lb: int = 2) -> None:
        self.num_lbs = num_lbs
        self.fps_per_lb = fps_per_lb
        self.total_fps = num_lbs * fps_per_lb

        self.rule_manager = RuleManager()
        self.stats = DPIStats()

        # Shared app stats (protected by lock)
        self._app_stats: dict[AppType, int] = {}
        self._app_lock = threading.Lock()
        self._detected_snis: dict[str, AppType] = {}

        # Output queue
        self._output_queue: queue.Queue[Optional[PacketJob]] = queue.Queue(maxsize=10_000)

        # Create FP threads
        self._fps: list[_FastPath] = []
        for i in range(self.total_fps):
            fp = _FastPath(
                i, self.rule_manager, self.stats,
                self._app_stats, self._app_lock, self._detected_snis,
                self._output_queue,
            )
            self._fps.append(fp)

        # Create LB threads, each managing a subset of FPs
        self._lbs: list[_LoadBalancer] = []
        for lb_id in range(num_lbs):
            start = lb_id * fps_per_lb
            lb_fps = self._fps[start: start + fps_per_lb]
            self._lbs.append(_LoadBalancer(lb_id, lb_fps))

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------

    def block_ip(self, ip: str) -> None:
        self.rule_manager.block_ip(ip)

    def block_app(self, app: str) -> None:
        self.rule_manager.block_app(app)

    def block_domain(self, domain: str) -> None:
        self.rule_manager.block_domain(domain)

    def process_file(self, input_path: str, output_path: str) -> None:
        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║              DPI ENGINE v2.0 (Multi-threaded)               ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Load Balancers: {self.num_lbs:>2}    FPs per LB: {self.fps_per_lb:>2}"
              f"    Total FPs: {self.total_fps:>2}     ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print()

        # Open input
        reader = PcapReader()
        if not reader.open(input_path):
            return

        # Open output
        writer = PcapWriter()
        if not writer.open(output_path, global_header=reader.global_header):
            reader.close()
            return

        # Start threads
        for fp in self._fps:
            fp.start()
        for lb in self._lbs:
            lb.start()

        # Start output writer thread
        output_running = threading.Event()
        output_running.set()

        def output_writer():
            while output_running.is_set() or not self._output_queue.empty():
                try:
                    job = self._output_queue.get(timeout=0.05)
                except queue.Empty:
                    continue
                if job is _SENTINEL:
                    break
                writer.write_packet(job.ts_sec, job.ts_usec, job.data)

        output_thread = threading.Thread(target=output_writer, name="Writer", daemon=True)
        output_thread.start()

        # Read and dispatch packets
        print("[Reader] Processing packets...")
        pkt_id = 0

        for raw in reader:
            parsed = PacketParser.parse(
                raw.data, ts_sec=raw.header.ts_sec, ts_usec=raw.header.ts_usec
            )
            if parsed is None or not parsed.has_ip:
                continue
            if not parsed.has_tcp and not parsed.has_udp:
                continue

            # Build PacketJob
            job = PacketJob(
                packet_id=pkt_id,
                tuple=_make_tuple(parsed),
                data=raw.data,
                tcp_flags=parsed.tcp_flags,
                payload_offset=parsed.payload_offset,
                payload_length=parsed.payload_length,
                ts_sec=raw.header.ts_sec,
                ts_usec=raw.header.ts_usec,
            )
            pkt_id += 1

            # Update global stats
            self.stats.total_packets += 1
            self.stats.total_bytes += len(raw.data)
            if parsed.has_tcp:
                self.stats.tcp_packets += 1
            elif parsed.has_udp:
                self.stats.udp_packets += 1

            # Dispatch to LB (hash-based)
            lb_idx = hash(job.tuple) % len(self._lbs)
            self._lbs[lb_idx].input_queue.put(job)

        print(f"[Reader] Done reading {pkt_id} packets")
        reader.close()

        # Wait for queues to drain
        import time
        time.sleep(0.5)

        # Stop all threads
        for lb in self._lbs:
            lb.stop()
        for fp in self._fps:
            fp.stop()

        output_running.clear()
        self._output_queue.put(_SENTINEL)
        output_thread.join(timeout=2)

        writer.close()

        # Print report
        self._print_report(output_path)

    # -----------------------------------------------------------------
    # Report
    # -----------------------------------------------------------------

    def _print_report(self, output_path: str) -> None:
        total = self.stats.total_packets

        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                      PROCESSING REPORT                     ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Total Packets:      {self.stats.total_packets:>12}                         ║")
        print(f"║ Total Bytes:        {self.stats.total_bytes:>12}                         ║")
        print(f"║ TCP Packets:        {self.stats.tcp_packets:>12}                         ║")
        print(f"║ UDP Packets:        {self.stats.udp_packets:>12}                         ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Forwarded:          {self.stats.forwarded_packets:>12}                         ║")
        print(f"║ Dropped:            {self.stats.dropped_packets:>12}                         ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║ THREAD STATISTICS                                          ║")

        for lb in self._lbs:
            print(f"║   LB{lb.id} dispatched:   {lb.dispatched:>12}                         ║")
        for fp in self._fps:
            print(f"║   FP{fp.id} processed:    {fp.processed:>12}                         ║")

        print("╠══════════════════════════════════════════════════════════════╣")
        print("║                   APPLICATION BREAKDOWN                    ║")
        print("╠══════════════════════════════════════════════════════════════╣")

        with self._app_lock:
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

        print(f"\nOutput written to: {output_path}")


# =============================================================================
# Helpers
# =============================================================================

def _make_tuple(parsed: ParsedPacket) -> FiveTuple:
    return FiveTuple(
        src_ip=str_to_ip(parsed.src_ip),
        dst_ip=str_to_ip(parsed.dest_ip),
        src_port=parsed.src_port,
        dst_port=parsed.dest_port,
        protocol=parsed.protocol,
    )
