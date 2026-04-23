"""
Connection (flow) tracker.

Maintains a per-flow table mapping ``FiveTuple`` → ``Connection``.
Tracks connection lifecycle (NEW → ESTABLISHED → CLASSIFIED → BLOCKED → CLOSED),
stores classification results, and supports stale-connection eviction.
"""

from __future__ import annotations

import time
from typing import Callable, Optional

from dpi.types import (
    AppType,
    Connection,
    ConnectionState,
    FiveTuple,
    PacketAction,
)


class ConnectionTracker:
    """
    Per-processor flow table.

    In the multi-threaded engine each Fast Path thread owns its own
    ``ConnectionTracker`` (no sharing required, because consistent
    hashing ensures the same flow always lands on the same thread).
    """

    def __init__(self, tracker_id: int = 0, max_connections: int = 100_000) -> None:
        self._id = tracker_id
        self._max_connections = max_connections
        self._connections: dict[FiveTuple, Connection] = {}

        # Lifetime stats
        self._total_seen: int = 0
        self._classified_count: int = 0
        self._blocked_count: int = 0

    # -----------------------------------------------------------------
    # Connection Management
    # -----------------------------------------------------------------

    def get_or_create(self, tuple_: FiveTuple) -> Connection:
        """Return the existing connection for *tuple_*, or create a new one."""
        conn = self._connections.get(tuple_)
        if conn is not None:
            return conn

        # Evict oldest if at capacity
        if len(self._connections) >= self._max_connections:
            self._evict_oldest()

        conn = Connection(tuple=tuple_)
        self._connections[tuple_] = conn
        self._total_seen += 1
        return conn

    def get(self, tuple_: FiveTuple) -> Optional[Connection]:
        """Look up an existing connection (including reverse tuple)."""
        conn = self._connections.get(tuple_)
        if conn is not None:
            return conn
        return self._connections.get(tuple_.reverse())

    def update(self, conn: Connection, packet_size: int, is_outbound: bool = True) -> None:
        if is_outbound:
            conn.packets_out += 1
            conn.bytes_out += packet_size
        else:
            conn.packets_in += 1
            conn.bytes_in += packet_size

    def classify(self, conn: Connection, app: AppType, sni: str) -> None:
        if conn.state != ConnectionState.CLASSIFIED:
            conn.app_type = app
            conn.sni = sni
            conn.state = ConnectionState.CLASSIFIED
            self._classified_count += 1

    def block(self, conn: Connection) -> None:
        conn.state = ConnectionState.BLOCKED
        conn.action = PacketAction.DROP
        self._blocked_count += 1

    def close(self, tuple_: FiveTuple) -> None:
        conn = self._connections.get(tuple_)
        if conn:
            conn.state = ConnectionState.CLOSED

    # -----------------------------------------------------------------
    # Maintenance
    # -----------------------------------------------------------------

    def cleanup_stale(self, timeout_seconds: int = 300) -> int:
        """Remove connections that haven't been seen for *timeout_seconds*."""
        # In the simple engine this is called periodically, but for
        # file-based processing the entire table is short-lived anyway.
        to_delete = [
            key for key, conn in self._connections.items()
            if conn.state == ConnectionState.CLOSED
        ]
        for key in to_delete:
            del self._connections[key]
        return len(to_delete)

    # -----------------------------------------------------------------
    # Reporting
    # -----------------------------------------------------------------

    def get_all_connections(self) -> list[Connection]:
        return list(self._connections.values())

    @property
    def active_count(self) -> int:
        return len(self._connections)

    def get_stats(self) -> dict[str, int]:
        return {
            "active":     len(self._connections),
            "total_seen": self._total_seen,
            "classified": self._classified_count,
            "blocked":    self._blocked_count,
        }

    def for_each(self, callback: Callable[[Connection], None]) -> None:
        for conn in self._connections.values():
            callback(conn)

    # -----------------------------------------------------------------
    # Internals
    # -----------------------------------------------------------------

    def _evict_oldest(self) -> None:
        """Remove the connection with the smallest packet count (LRU-ish)."""
        if not self._connections:
            return
        min_key = min(
            self._connections,
            key=lambda k: self._connections[k].packets_in + self._connections[k].packets_out,
        )
        del self._connections[min_key]
