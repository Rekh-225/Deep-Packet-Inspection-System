"""
Blocking / filtering rule manager.

Supports four rule types:
  - IP-based:     block all traffic from a specific source IP
  - App-based:    block a detected application (e.g. YouTube)
  - Domain-based: block traffic matching a domain (substring or wildcard)
  - Port-based:   block a specific destination port

Thread-safe — all reads and writes are protected by a lock, ready for
the multi-threaded engine variant.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Optional

from dpi.types import AppType, app_name_to_type, ip_to_str, str_to_ip


# =============================================================================
# Block Reason
# =============================================================================

@dataclass
class BlockReason:
    """Why a packet was blocked."""
    type:   str    # "ip", "app", "domain", "port"
    detail: str    # Human-readable detail


# =============================================================================
# Rule Manager
# =============================================================================

class RuleManager:
    """
    Manages blocking rules and evaluates packets against them.

    All public methods are thread-safe.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._blocked_ips:      set[int] = set()
        self._blocked_apps:     set[AppType] = set()
        self._blocked_domains:  set[str] = set()
        self._domain_patterns:  list[str] = []   # Wildcard patterns like *.facebook.com
        self._blocked_ports:    set[int] = set()

    # -------------------------------------------------------------------------
    # IP blocking
    # -------------------------------------------------------------------------

    def block_ip(self, ip: str) -> None:
        with self._lock:
            self._blocked_ips.add(str_to_ip(ip))
        print(f"[RuleManager] Blocked IP: {ip}")

    def unblock_ip(self, ip: str) -> None:
        with self._lock:
            self._blocked_ips.discard(str_to_ip(ip))
        print(f"[RuleManager] Unblocked IP: {ip}")

    def is_ip_blocked(self, ip: int) -> bool:
        with self._lock:
            return ip in self._blocked_ips

    def get_blocked_ips(self) -> list[str]:
        with self._lock:
            return [ip_to_str(ip) for ip in self._blocked_ips]

    # -------------------------------------------------------------------------
    # Application blocking
    # -------------------------------------------------------------------------

    def block_app(self, app: AppType | str) -> None:
        if isinstance(app, str):
            resolved = app_name_to_type(app)
            if resolved is None:
                print(f"[RuleManager] Unknown app: {app}")
                return
            app = resolved
        with self._lock:
            self._blocked_apps.add(app)
        print(f"[RuleManager] Blocked app: {app.value}")

    def unblock_app(self, app: AppType | str) -> None:
        if isinstance(app, str):
            resolved = app_name_to_type(app)
            if resolved is None:
                return
            app = resolved
        with self._lock:
            self._blocked_apps.discard(app)
        print(f"[RuleManager] Unblocked app: {app.value}")

    def is_app_blocked(self, app: AppType) -> bool:
        with self._lock:
            return app in self._blocked_apps

    def get_blocked_apps(self) -> list[AppType]:
        with self._lock:
            return list(self._blocked_apps)

    # -------------------------------------------------------------------------
    # Domain blocking
    # -------------------------------------------------------------------------

    def block_domain(self, domain: str) -> None:
        with self._lock:
            if "*" in domain:
                self._domain_patterns.append(domain)
            else:
                self._blocked_domains.add(domain.lower())
        print(f"[RuleManager] Blocked domain: {domain}")

    def unblock_domain(self, domain: str) -> None:
        with self._lock:
            if "*" in domain:
                try:
                    self._domain_patterns.remove(domain)
                except ValueError:
                    pass
            else:
                self._blocked_domains.discard(domain.lower())
        print(f"[RuleManager] Unblocked domain: {domain}")

    def is_domain_blocked(self, domain: str) -> bool:
        lower = domain.lower()
        with self._lock:
            # Exact match
            if lower in self._blocked_domains:
                return True
            # Substring match on exact domains
            for blocked in self._blocked_domains:
                if blocked in lower:
                    return True
            # Wildcard patterns
            for pattern in self._domain_patterns:
                if self._domain_matches_pattern(lower, pattern.lower()):
                    return True
        return False

    def get_blocked_domains(self) -> list[str]:
        with self._lock:
            return list(self._blocked_domains) + list(self._domain_patterns)

    # -------------------------------------------------------------------------
    # Port blocking
    # -------------------------------------------------------------------------

    def block_port(self, port: int) -> None:
        with self._lock:
            self._blocked_ports.add(port)
        print(f"[RuleManager] Blocked port: {port}")

    def unblock_port(self, port: int) -> None:
        with self._lock:
            self._blocked_ports.discard(port)

    def is_port_blocked(self, port: int) -> bool:
        with self._lock:
            return port in self._blocked_ports

    # -------------------------------------------------------------------------
    # Combined check
    # -------------------------------------------------------------------------

    def should_block(
        self,
        src_ip: int,
        dst_port: int,
        app: AppType,
        domain: str,
    ) -> Optional[BlockReason]:
        """
        Check all rules and return a ``BlockReason`` if the packet should be
        blocked, or ``None`` if it should be forwarded.
        """
        if self.is_ip_blocked(src_ip):
            return BlockReason("ip", ip_to_str(src_ip))
        if self.is_port_blocked(dst_port):
            return BlockReason("port", str(dst_port))
        if self.is_app_blocked(app):
            return BlockReason("app", app.value)
        if domain and self.is_domain_blocked(domain):
            return BlockReason("domain", domain)
        return None

    # -------------------------------------------------------------------------
    # Persistence
    # -------------------------------------------------------------------------

    def save_rules(self, filename: str) -> bool:
        try:
            with open(filename, "w") as f:
                f.write("[BLOCKED_IPS]\n")
                for ip in self.get_blocked_ips():
                    f.write(ip + "\n")
                f.write("\n[BLOCKED_APPS]\n")
                for app in self.get_blocked_apps():
                    f.write(app.value + "\n")
                f.write("\n[BLOCKED_DOMAINS]\n")
                for dom in self.get_blocked_domains():
                    f.write(dom + "\n")
                f.write("\n[BLOCKED_PORTS]\n")
                with self._lock:
                    for port in self._blocked_ports:
                        f.write(str(port) + "\n")
            print(f"[RuleManager] Rules saved to: {filename}")
            return True
        except OSError:
            return False

    def load_rules(self, filename: str) -> bool:
        try:
            with open(filename, "r") as f:
                section = ""
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("["):
                        section = line
                        continue
                    if section == "[BLOCKED_IPS]":
                        self.block_ip(line)
                    elif section == "[BLOCKED_APPS]":
                        self.block_app(line)
                    elif section == "[BLOCKED_DOMAINS]":
                        self.block_domain(line)
                    elif section == "[BLOCKED_PORTS]":
                        self.block_port(int(line))
            print(f"[RuleManager] Rules loaded from: {filename}")
            return True
        except OSError:
            return False

    # -------------------------------------------------------------------------
    # Statistics
    # -------------------------------------------------------------------------

    def get_stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "blocked_ips": len(self._blocked_ips),
                "blocked_apps": len(self._blocked_apps),
                "blocked_domains": len(self._blocked_domains) + len(self._domain_patterns),
                "blocked_ports": len(self._blocked_ports),
            }

    def clear_all(self) -> None:
        with self._lock:
            self._blocked_ips.clear()
            self._blocked_apps.clear()
            self._blocked_domains.clear()
            self._domain_patterns.clear()
            self._blocked_ports.clear()
        print("[RuleManager] All rules cleared")

    # -------------------------------------------------------------------------
    # Internals
    # -------------------------------------------------------------------------

    @staticmethod
    def _domain_matches_pattern(domain: str, pattern: str) -> bool:
        """Check if *domain* matches a wildcard pattern like ``*.example.com``."""
        if len(pattern) >= 2 and pattern[0] == "*" and pattern[1] == ".":
            suffix = pattern[1:]  # .example.com
            if domain.endswith(suffix):
                return True
            # Bare domain also matches: example.com matches *.example.com
            if domain == pattern[2:]:
                return True
        return False
