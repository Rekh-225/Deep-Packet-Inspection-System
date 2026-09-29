"""
Shared per-packet inspection and decision logic.

Both engines (``dpi.engine.DPIEngine`` and ``dpi.engine_mt.DPIEngineMT``)
must classify flows and apply rules identically.  This module is the single
implementation of that logic so the two engines cannot drift apart.

A ``FlowProcessor`` owns one ``ConnectionTracker`` and is *not* thread-safe:
the single-threaded engine owns one, and each fast-path thread in the
multi-threaded engine owns its own (flow affinity guarantees a given flow is
only ever seen by one processor).

Packet accounting categories used by both engines:

``RETAINED``     supported packet, not matched by any rule, written to output
``FILTERED``     supported packet, dropped because its flow matched a rule
``UNSUPPORTED``  parsed, but not IPv4 + (TCP | UDP) -- never inspected, not written
``MALFORMED``    could not be parsed (truncated / inconsistent headers) -- not written
``FAILED``       admitted but never decided because the run aborted (MT engine only)

Unsupported and malformed packets are excluded from the output on purpose: the
engine only forwards traffic it was able to inspect.  They are counted so the
report can never claim "no loss" for protocols the parser does not handle.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Tuple

from dpi.connection_tracker import ConnectionTracker
from dpi.packet_parser import ParsedPacket
from dpi.rule_manager import BlockReason, RuleManager
from dpi.sni_extractor import DNSExtractor, HTTPHostExtractor, SNIExtractor
from dpi.types import (
    AppType, Connection, ConnectionState, FiveTuple, FlowCapacity, sni_to_app_type, str_to_ip,
)


class DetectionLog:
    """
    Bounded name -> app record of detections for reports.

    Keeps at most ``limit`` distinct names (first seen wins a slot; a repeat of
    a kept name updates its app, matching the previous last-writer semantics).
    Detections beyond the limit are counted in ``dropped`` so reports can show
    that the detail is truncated while ``total`` stays accurate.
    """

    DEFAULT_LIMIT = 10_000

    def __init__(self, limit: int = DEFAULT_LIMIT) -> None:
        if limit < 0:
            raise ValueError("limit must be >= 0")
        self.limit = limit
        self.items: Dict[str, AppType] = {}
        self.total = 0
        self.dropped = 0

    def add(self, name: str, app: AppType) -> None:
        self.total += 1
        if name in self.items:
            self.items[name] = app
        elif len(self.items) < self.limit:
            self.items[name] = app
        else:
            self.dropped += 1

    @property
    def truncated(self) -> bool:
        return self.dropped > 0


class Outcome(Enum):
    RETAINED = "retained"
    FILTERED = "filtered"
    UNSUPPORTED = "unsupported"
    MALFORMED = "malformed"
    FAILED = "failed"


def categorize(parsed: Optional[ParsedPacket]) -> Optional[Outcome]:
    """
    Return ``MALFORMED`` / ``UNSUPPORTED`` for packets the engine will not
    inspect, or ``None`` if the packet is IPv4 TCP/UDP and should be processed.
    """
    if parsed is None:
        return Outcome.MALFORMED
    if not parsed.has_ip or not (parsed.has_tcp or parsed.has_udp):
        return Outcome.UNSUPPORTED
    return None


def make_tuple(parsed: ParsedPacket) -> FiveTuple:
    """Build the directional FiveTuple used as the flow-table key."""
    return FiveTuple(
        src_ip=str_to_ip(parsed.src_ip),
        dst_ip=str_to_ip(parsed.dest_ip),
        src_port=parsed.src_port,
        dst_port=parsed.dest_port,
        protocol=parsed.protocol,
    )


@dataclass
class Decision:
    conn: Connection
    blocked: bool
    newly_blocked: bool
    reason: Optional[BlockReason]
    detected: Optional[Tuple[str, AppType]]   # (domain, app) if a name was extracted from this packet

    @property
    def outcome(self) -> Outcome:
        return Outcome.FILTERED if self.blocked else Outcome.RETAINED


class FlowProcessor:
    """
    Stateful classifier + rule evaluator for a set of flows.

    Flow identity is the *directional* five-tuple (src, dst, sport, dport, proto):
    the two directions of a TCP connection are tracked as two flows.  A rule
    match on one direction (e.g. the client's TLS Client Hello) therefore
    only blocks that direction -- this mirrors the original single-threaded
    behaviour and is preserved deliberately.
    """

    def __init__(
        self,
        rules: RuleManager,
        tracker: Optional[ConnectionTracker] = None,
        capacity: Optional[FlowCapacity] = None,
    ) -> None:
        self.rules = rules
        self.tracker = tracker if tracker is not None else ConnectionTracker(capacity=capacity)

    def process(
        self,
        tuple_: FiveTuple,
        has_tcp: bool,
        payload: bytes,
        size: int,
        packet_id: int = -1,
    ) -> Decision:
        conn = self.tracker.get_or_create(tuple_)
        self.tracker.update(conn, size)
        if packet_id >= 0:
            if conn.first_packet_id < 0:
                conn.first_packet_id = packet_id
            conn.last_packet_id = packet_id

        detected = self._inspect(conn, tuple_, has_tcp, payload)

        newly_blocked = False
        reason = None
        if conn.state != ConnectionState.BLOCKED:
            reason = self.rules.should_block(tuple_.src_ip, tuple_.dst_port, conn.app_type, conn.sni)
            if reason:
                self.tracker.block(conn)
                conn.block_rule_type = reason.type
                conn.block_rule_detail = reason.detail
                newly_blocked = True

        return Decision(
            conn=conn,
            blocked=conn.state == ConnectionState.BLOCKED,
            newly_blocked=newly_blocked,
            reason=reason,
            detected=detected,
        )

    def _inspect(
        self, conn: Connection, tuple_: FiveTuple, has_tcp: bool, payload: bytes
    ) -> Optional[Tuple[str, AppType]]:
        """Try to classify the flow from the packet payload."""
        # Already classified with a specific app? Skip.
        if conn.sni and conn.app_type not in (AppType.UNKNOWN, AppType.HTTPS, AppType.HTTP):
            return None

        # TLS SNI (HTTPS on port 443)
        if has_tcp and tuple_.dst_port == 443 and len(payload) > 5:
            sni = SNIExtractor.extract(payload)
            if sni:
                conn.sni = sni
                conn.tls_sni = sni
                conn.app_type = sni_to_app_type(sni)
                conn.classified_by = "tls_sni"
                self.tracker.classify(conn, conn.app_type, sni)
                return sni, conn.app_type

        # HTTP Host (port 80)
        if has_tcp and tuple_.dst_port == 80 and len(payload) > 10:
            host = HTTPHostExtractor.extract(payload)
            if host:
                conn.sni = host
                conn.http_host = host
                conn.app_type = sni_to_app_type(host)
                conn.classified_by = "http_host"
                self.tracker.classify(conn, conn.app_type, host)
                return host, conn.app_type

        # DNS (port 53)
        if tuple_.dst_port == 53 or tuple_.src_port == 53:
            detected = None
            if conn.app_type == AppType.UNKNOWN:
                conn.app_type = AppType.DNS
                conn.classified_by = "dns_port"
                domain = DNSExtractor.extract_query(payload) if payload else None
                if domain:
                    conn.sni = domain
                    conn.dns_query = domain
                    detected = (domain, AppType.DNS)
                self.tracker.classify(conn, AppType.DNS, conn.sni)
            return detected

        # Port-based fallback (don't mark as fully classified — SNI may come later)
        if conn.app_type == AppType.UNKNOWN:
            if tuple_.dst_port == 443:
                conn.app_type = AppType.HTTPS
                conn.classified_by = "port_fallback"
            elif tuple_.dst_port == 80:
                conn.app_type = AppType.HTTP
                conn.classified_by = "port_fallback"
        return None
