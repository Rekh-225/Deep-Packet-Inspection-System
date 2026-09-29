"""
Single-threaded DPI Engine.

Reads a PCAP file, parses each packet, classifies flows via SNI / HTTP Host /
DNS inspection, applies blocking rules, and writes allowed packets to an
output PCAP — all in a single sequential pass.

This is the "simple" version, ideal for learning and small captures.  It is
also the reference implementation: the multi-threaded engine must produce
identical decisions and accounting (both use ``dpi.inspection.FlowProcessor``).
"""

from __future__ import annotations

import sys
from collections import defaultdict
from typing import Iterator, Optional

# Ensure UTF-8 output on Windows (box-drawing characters)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from dpi.types import (
    AppType, Connection, DPIStats, FlowCapacity, ProcessingCancelled, ProcessingError,
)
from dpi.pcap_io import PcapReader, PcapWriteError, PcapWriter
from dpi.packet_parser import PacketParser
from dpi.rule_manager import RuleManager
from dpi.connection_tracker import ConnectionTracker
from dpi.inspection import DetectionLog, FlowProcessor, Outcome, categorize, make_tuple


class DPIEngine:
    """
    Deep Packet Inspection engine (single-threaded).

    Usage::

        engine = DPIEngine()
        engine.rule_manager.block_app("YouTube")
        engine.process_file("input.pcap", "output.pcap")

    ``process_file`` raises ``ProcessingError`` if the input or output file
    cannot be opened.  Output is written to ``<output>.partial`` and moved into
    place only after the whole input has been processed.
    """

    def __init__(
        self,
        max_flows: int = FlowCapacity.DEFAULT_MAX_FLOWS,
        max_report_detail: int = DetectionLog.DEFAULT_LIMIT,
    ) -> None:
        self.rule_manager = RuleManager()
        self.stats = DPIStats()
        self.flow_capacity = FlowCapacity(max_flows)
        self.max_report_detail = max_report_detail
        self._tracker = ConnectionTracker(capacity=self.flow_capacity)
        self._processor = FlowProcessor(self.rule_manager, self._tracker)
        self._app_stats: dict[AppType, int] = defaultdict(int)
        self._detections = DetectionLog(max_report_detail)
        self._run_total = 0
        self.abort_summary: dict = {}

    @property
    def _detected_snis(self) -> dict[str, AppType]:
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

    @property
    def mode(self) -> str:
        return "simple"

    @property
    def app_stats(self) -> dict[AppType, int]:
        """Per-packet heuristic class counts."""
        return dict(self._app_stats)

    def connections(self) -> Iterator[Connection]:
        """All tracked flows (insertion order == first-seen order in this engine)."""
        return self._tracker.iter_connections()

    @property
    def flow_count(self) -> int:
        return self._tracker.active_count

    def process_file(self, input_path: str, output_path: str) -> None:
        """Run the full DPI pipeline on *input_path* and write to *output_path*."""

        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                    DPI ENGINE v2.0                          ║")
        print("║            Deep Packet Inspection System                    ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print()

        reader = PcapReader()
        if not reader.open(input_path):
            raise ProcessingError(f"could not open input PCAP: {input_path}: {reader.last_error}")

        writer = PcapWriter()
        if not writer.open(output_path, global_header=reader.global_header, atomic=True):
            reader.close()
            raise ProcessingError(f"could not open output PCAP: {output_path}: {writer.last_error}")

        print(f"\n[DPI] Processing packets...\n")

        self._run_total = 0
        committed = False
        try:
            self._process(reader, writer)
            writer.commit()                      # raises PcapWriteError on failure (temp handled)
            committed = True
        except KeyboardInterrupt:
            if committed:
                raise
            leftover = writer.discard()
            self._record_abort()
            raise ProcessingCancelled(
                self._abort_message("processing cancelled (interrupted)", leftover)
            ) from None
        except PcapWriteError:
            self._record_abort()
            raise
        except ProcessingError as e:
            leftover = writer.discard()
            self._record_abort()
            raise type(e)(self._abort_message(str(e), leftover)) from e
        except OSError as e:
            leftover = writer.discard()
            self._record_abort()
            raise PcapWriteError(self._abort_message(f"I/O error while processing: {e}", leftover)) from e
        except BaseException as e:
            leftover = writer.discard()
            self._record_abort()
            raise ProcessingError(
                self._abort_message(f"unexpected {type(e).__name__}: {e}", leftover)
            ) from e
        finally:
            reader.close()

        self.stats.active_connections = self._tracker.active_count
        self._print_report(output_path)

    def _process(self, reader: PcapReader, writer: PcapWriter) -> None:
        for raw in reader:
            pkt_id = self._run_total
            self._run_total += 1
            self.stats.total_packets += 1
            self.stats.total_bytes += len(raw.data)

            parsed = PacketParser.parse(
                raw.data, ts_sec=raw.header.ts_sec, ts_usec=raw.header.ts_usec
            )
            skip = categorize(parsed)
            if skip is Outcome.MALFORMED:
                self.stats.malformed_packets += 1
                continue
            if skip is Outcome.UNSUPPORTED:
                self.stats.unsupported_packets += 1
                continue

            if parsed.has_tcp:
                self.stats.tcp_packets += 1
            else:
                self.stats.udp_packets += 1

            tuple_ = make_tuple(parsed)
            payload = (raw.data[parsed.payload_offset: parsed.payload_offset + parsed.payload_length]
                       if parsed.payload_length > 0 else b"")
            decision = self._processor.process(tuple_, parsed.has_tcp, payload, len(raw.data), pkt_id)
            conn = decision.conn

            if decision.detected:
                self._detections.add(decision.detected[0], decision.detected[1])
            if decision.newly_blocked:
                print(
                    f"[BLOCKED] {parsed.src_ip} -> {parsed.dest_ip}"
                    f" ({conn.app_type.value}"
                    f"{': ' + conn.sni if conn.sni else ''})"
                )

            self._app_stats[conn.app_type] += 1

            if decision.blocked:
                self.stats.dropped_packets += 1
            else:
                self.stats.forwarded_packets += 1
                writer.write_packet(raw.header.ts_sec, raw.header.ts_usec, raw.data, raw.header.orig_len)

    def _record_abort(self) -> None:
        """
        Aborted-run accounting.  In the single-threaded engine every admitted
        packet is decided and retired synchronously, so the only packet that can
        be admitted but not retired is the one being processed when the run
        stopped (or none).
        """
        s = self.stats
        retired = s.forwarded_packets + s.dropped_packets + s.unsupported_packets + s.malformed_packets
        s.failed_packets = s.total_packets - retired
        self.abort_summary = {
            "admitted": self._run_total,
            "decided": retired,
            "retired": retired,
            "decided_unretired": 0,
            "undecided": self._run_total - retired,
            "input_fully_read": False,
        }

    def _abort_message(self, reason: str, leftover: Optional[str]) -> str:
        a = self.abort_summary
        msg = (f"{reason}; admitted {a['admitted']} packet(s) (input not fully read), "
               f"{a['retired']} decided and retired, {a['undecided']} undecided; output discarded")
        return f"{msg}; {leftover}" if leftover else msg

    # -----------------------------------------------------------------
    # Report
    # -----------------------------------------------------------------

    def _print_report(self, output_path: str) -> None:
        total = self.stats.total_packets
        flows = self._tracker.active_count

        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                      PROCESSING REPORT                     ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Total Packets:      {self.stats.total_packets:>10}                           ║")
        print(f"║ Total Bytes:        {self.stats.total_bytes:>10}                           ║")
        print(f"║ TCP Packets:        {self.stats.tcp_packets:>10}                           ║")
        print(f"║ UDP Packets:        {self.stats.udp_packets:>10}                           ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Retained (written): {self.stats.forwarded_packets:>10}                           ║")
        print(f"║ Rule-filtered:      {self.stats.dropped_packets:>10}                           ║")
        print(f"║ Unsupported:        {self.stats.unsupported_packets:>10}                           ║")
        print(f"║ Malformed:          {self.stats.malformed_packets:>10}                           ║")
        print(f"║ Active Flows:       {flows:>10}                           ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║                   APPLICATION BREAKDOWN                    ║")
        print("╠══════════════════════════════════════════════════════════════╣")

        sorted_apps = sorted(self._app_stats.items(), key=lambda x: x[1], reverse=True)
        for app, count in sorted_apps:
            pct = (100.0 * count / total) if total > 0 else 0
            bar = "#" * int(pct / 5)
            print(f"║ {app.value:<15} {count:>8} {pct:>5.1f}% {bar:<20}  ║")

        print("╚══════════════════════════════════════════════════════════════╝")

        # Detected domains
        if self._detected_snis:
            print("\n[Detected Applications/Domains]")
            for sni, app in self._detected_snis.items():
                print(f"  - {sni} -> {app.value}")
            if self._detections.truncated:
                print(f"  ... {self._detections.dropped} further detection(s) not listed "
                      f"(limit {self._detections.limit}, see --max-report-detail)")

        if self.stats.unsupported_packets or self.stats.malformed_packets:
            print(f"\nNote: {self.stats.unsupported_packets} unsupported and "
                  f"{self.stats.malformed_packets} malformed packet(s) were not inspected "
                  f"and are not in the output.")
        print(f"\nOutput written to: {output_path}")
