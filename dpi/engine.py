"""
Single-threaded DPI Engine.

Reads a PCAP file, parses each packet, classifies flows via SNI / HTTP Host /
DNS inspection, applies blocking rules, and writes allowed packets to an
output PCAP — all in a single sequential pass.

This is the "simple" version, ideal for learning and small captures.
"""

from __future__ import annotations

import sys
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
    ConnectionState,
    DPIStats,
    FiveTuple,
    PacketAction,
    ip_to_str,
    sni_to_app_type,
    str_to_ip,
)
from dpi.pcap_io import PcapReader, PcapWriter
from dpi.packet_parser import PacketParser, ParsedPacket
from dpi.sni_extractor import SNIExtractor, HTTPHostExtractor, DNSExtractor
from dpi.rule_manager import RuleManager
from dpi.connection_tracker import ConnectionTracker


class DPIEngine:
    """
    Deep Packet Inspection engine (single-threaded).

    Usage::

        engine = DPIEngine()
        engine.rule_manager.block_app("YouTube")
        engine.process_file("input.pcap", "output.pcap")
    """

    def __init__(self) -> None:
        self.rule_manager = RuleManager()
        self.stats = DPIStats()
        self._tracker = ConnectionTracker()
        self._app_stats: dict[AppType, int] = defaultdict(int)
        self._detected_snis: dict[str, AppType] = {}

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
            return

        writer = PcapWriter()
        if not writer.open(output_path, global_header=reader.global_header):
            reader.close()
            return

        print(f"\n[DPI] Processing packets...\n")

        for raw in reader:
            self.stats.total_packets += 1
            self.stats.total_bytes += len(raw.data)

            # Parse protocol headers
            parsed = PacketParser.parse(
                raw.data, ts_sec=raw.header.ts_sec, ts_usec=raw.header.ts_usec
            )
            if parsed is None or not parsed.has_ip:
                continue
            if not parsed.has_tcp and not parsed.has_udp:
                continue

            if parsed.has_tcp:
                self.stats.tcp_packets += 1
            elif parsed.has_udp:
                self.stats.udp_packets += 1

            # Build five-tuple
            tuple_ = _make_tuple(parsed)

            # Get or create flow
            conn = self._tracker.get_or_create(tuple_)
            self._tracker.update(conn, len(raw.data))

            # --- Deep inspection ---
            self._inspect(raw.data, parsed, conn)

            # --- Check blocking rules ---
            if conn.state != ConnectionState.BLOCKED:
                reason = self.rule_manager.should_block(
                    tuple_.src_ip, tuple_.dst_port, conn.app_type, conn.sni,
                )
                if reason:
                    self._tracker.block(conn)
                    print(
                        f"[BLOCKED] {parsed.src_ip} -> {parsed.dest_ip}"
                        f" ({conn.app_type.value}"
                        f"{': ' + conn.sni if conn.sni else ''})"
                    )

            # Update per-app stats
            self._app_stats[conn.app_type] += 1

            # Forward or drop
            if conn.state == ConnectionState.BLOCKED:
                self.stats.dropped_packets += 1
            else:
                self.stats.forwarded_packets += 1
                writer.write_packet(raw.header.ts_sec, raw.header.ts_usec, raw.data)

        reader.close()
        writer.close()

        self._print_report(output_path)

    # -----------------------------------------------------------------
    # Inspection
    # -----------------------------------------------------------------

    def _inspect(self, data: bytes, parsed: ParsedPacket, conn) -> None:
        """Try to classify the flow from the packet payload."""
        # Already classified with a specific app? Skip.
        if conn.sni and conn.app_type not in (AppType.UNKNOWN, AppType.HTTPS, AppType.HTTP):
            return

        payload = data[parsed.payload_offset:] if parsed.payload_length > 0 else b""

        # TLS SNI (HTTPS on port 443)
        if parsed.has_tcp and parsed.dest_port == 443 and len(payload) > 5:
            sni = SNIExtractor.extract(payload)
            if sni:
                conn.sni = sni
                conn.app_type = sni_to_app_type(sni)
                self._detected_snis[sni] = conn.app_type
                self._tracker.classify(conn, conn.app_type, sni)
                return

        # HTTP Host (port 80)
        if parsed.has_tcp and parsed.dest_port == 80 and len(payload) > 10:
            host = HTTPHostExtractor.extract(payload)
            if host:
                conn.sni = host
                conn.app_type = sni_to_app_type(host)
                self._detected_snis[host] = conn.app_type
                self._tracker.classify(conn, conn.app_type, host)
                return

        # DNS (port 53)
        if parsed.dest_port == 53 or parsed.src_port == 53:
            if conn.app_type == AppType.UNKNOWN:
                conn.app_type = AppType.DNS
                domain = DNSExtractor.extract_query(payload) if payload else None
                if domain:
                    conn.sni = domain
                    self._detected_snis[domain] = AppType.DNS
                self._tracker.classify(conn, AppType.DNS, conn.sni)
            return

        # Port-based fallback (don't mark as fully classified — SNI may come later)
        if conn.app_type == AppType.UNKNOWN:
            if parsed.dest_port == 443:
                conn.app_type = AppType.HTTPS
            elif parsed.dest_port == 80:
                conn.app_type = AppType.HTTP

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
        print(f"║ Forwarded:          {self.stats.forwarded_packets:>10}                           ║")
        print(f"║ Dropped:            {self.stats.dropped_packets:>10}                           ║")
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

        print(f"\nOutput written to: {output_path}")


# =============================================================================
# Helpers
# =============================================================================

def _make_tuple(parsed: ParsedPacket) -> FiveTuple:
    """Build a FiveTuple from a ParsedPacket."""
    return FiveTuple(
        src_ip=str_to_ip(parsed.src_ip),
        dst_ip=str_to_ip(parsed.dest_ip),
        src_port=parsed.src_port,
        dst_port=parsed.dest_port,
        protocol=parsed.protocol,
    )
