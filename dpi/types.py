"""
Core data types for the DPI Engine.

Defines enumerations, data classes, and helper functions used
throughout the packet inspection pipeline.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# =============================================================================
# Application Classification
# =============================================================================

class AppType(Enum):
    """Detected application type based on SNI / Host / port heuristics."""
    UNKNOWN    = "Unknown"
    HTTP       = "HTTP"
    HTTPS      = "HTTPS"
    DNS        = "DNS"
    TLS        = "TLS"
    QUIC       = "QUIC"
    # Specific applications (detected via SNI)
    GOOGLE     = "Google"
    FACEBOOK   = "Facebook"
    YOUTUBE    = "YouTube"
    TWITTER    = "Twitter/X"
    INSTAGRAM  = "Instagram"
    NETFLIX    = "Netflix"
    AMAZON     = "Amazon"
    MICROSOFT  = "Microsoft"
    APPLE      = "Apple"
    WHATSAPP   = "WhatsApp"
    TELEGRAM   = "Telegram"
    TIKTOK     = "TikTok"
    SPOTIFY    = "Spotify"
    ZOOM       = "Zoom"
    DISCORD    = "Discord"
    GITHUB     = "GitHub"
    CLOUDFLARE = "Cloudflare"


class ConnectionState(Enum):
    """TCP connection lifecycle state."""
    NEW         = "new"
    ESTABLISHED = "established"
    CLASSIFIED  = "classified"
    BLOCKED     = "blocked"
    CLOSED      = "closed"


class PacketAction(Enum):
    """Decision made for each packet."""
    FORWARD  = "forward"
    DROP     = "drop"
    INSPECT  = "inspect"
    LOG_ONLY = "log_only"


# =============================================================================
# Five-Tuple: Uniquely identifies a network connection/flow
# =============================================================================

@dataclass(frozen=True)
class FiveTuple:
    """
    A network flow identifier.

    The five-tuple (src_ip, dst_ip, src_port, dst_port, protocol) uniquely
    identifies a connection. All packets sharing the same tuple belong to the
    same flow.
    """
    src_ip:   int  # uint32, host byte order
    dst_ip:   int  # uint32, host byte order
    src_port: int  # uint16
    dst_port: int  # uint16
    protocol: int  # 6 = TCP, 17 = UDP

    def reverse(self) -> FiveTuple:
        """Return the reverse tuple (swap src/dst) for bidirectional matching."""
        return FiveTuple(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol,
        )

    def to_string(self) -> str:
        proto = "TCP" if self.protocol == 6 else "UDP" if self.protocol == 17 else "?"
        return (
            f"{ip_to_str(self.src_ip)}:{self.src_port} -> "
            f"{ip_to_str(self.dst_ip)}:{self.dst_port} ({proto})"
        )

    def __repr__(self) -> str:
        return self.to_string()


# =============================================================================
# Connection Entry (tracked per flow)
# =============================================================================

@dataclass
class Connection:
    """Per-flow state maintained by the connection tracker."""
    tuple:       FiveTuple
    state:       ConnectionState = ConnectionState.NEW
    app_type:    AppType = AppType.UNKNOWN
    sni:         str = ""

    packets_in:  int = 0
    packets_out: int = 0
    bytes_in:    int = 0
    bytes_out:   int = 0

    action:      PacketAction = PacketAction.FORWARD

    # TCP state tracking
    syn_seen:     bool = False
    syn_ack_seen: bool = False
    fin_seen:     bool = False


# =============================================================================
# Packet wrapper for passing between processing stages
# =============================================================================

@dataclass
class PacketJob:
    """Self-contained packet with parsed metadata for processing."""
    packet_id:      int
    tuple:          FiveTuple
    data:           bytes           # Full raw packet bytes
    tcp_flags:      int = 0
    payload_offset: int = 0
    payload_length: int = 0
    ts_sec:         int = 0
    ts_usec:        int = 0


# =============================================================================
# Statistics
# =============================================================================

@dataclass
class DPIStats:
    """Engine-wide processing statistics."""
    total_packets:     int = 0
    total_bytes:       int = 0
    forwarded_packets: int = 0
    dropped_packets:   int = 0
    tcp_packets:       int = 0
    udp_packets:       int = 0
    other_packets:     int = 0
    active_connections: int = 0


# =============================================================================
# Helper Functions
# =============================================================================

def ip_to_str(ip: int) -> str:
    """Convert a uint32 IP (host byte order, little-endian stored) to dotted string."""
    return f"{ip & 0xFF}.{(ip >> 8) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 24) & 0xFF}"


def str_to_ip(ip_str: str) -> int:
    """Convert a dotted-decimal IP string to uint32 (host byte order)."""
    parts = [int(p) for p in ip_str.split(".")]
    return parts[0] | (parts[1] << 8) | (parts[2] << 16) | (parts[3] << 24)


def sni_to_app_type(sni: str) -> AppType:
    """
    Map a Server Name Indication (SNI) or HTTP Host to an application type.

    Uses substring matching on the lowercased SNI against known patterns
    for popular services.
    """
    if not sni:
        return AppType.UNKNOWN

    lower = sni.lower()

    # Order matters — check more specific patterns before generic ones.
    # YouTube (before Google, since YouTube domains contain google-related CDNs)
    if any(p in lower for p in ("youtube", "ytimg", "youtu.be", "yt3.ggpht")):
        return AppType.YOUTUBE

    # Google
    if any(p in lower for p in ("google", "gstatic", "googleapis", "ggpht", "gvt1")):
        return AppType.GOOGLE

    # Instagram (before Facebook/Meta)
    if any(p in lower for p in ("instagram", "cdninstagram")):
        return AppType.INSTAGRAM

    # WhatsApp (before Facebook/Meta)
    if any(p in lower for p in ("whatsapp", "wa.me")):
        return AppType.WHATSAPP

    # Facebook / Meta
    if any(p in lower for p in ("facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")):
        return AppType.FACEBOOK

    # Netflix (before Twitter — "t.co" would falsely match "netflix.com")
    if any(p in lower for p in ("netflix", "nflxvideo", "nflximg")):
        return AppType.NETFLIX

    # Microsoft (before Twitter — "t.co" would falsely match "microsoft.com")
    if any(p in lower for p in ("microsoft", "msn.com", "office", "azure",
                                 "live.com", "outlook", "bing")):
        return AppType.MICROSOFT

    # Amazon / AWS
    if any(p in lower for p in ("amazon", "amazonaws", "cloudfront", "aws")):
        return AppType.AMAZON

    # Twitter / X — use exact domain checks for short patterns
    if any(p in lower for p in ("twitter", "twimg")):
        return AppType.TWITTER
    if lower == "x.com" or lower.endswith(".x.com"):
        return AppType.TWITTER
    if lower == "t.co" or lower.endswith(".t.co"):
        return AppType.TWITTER

    # Apple
    if any(p in lower for p in ("apple", "icloud", "mzstatic", "itunes")):
        return AppType.APPLE

    # Telegram
    if any(p in lower for p in ("telegram", "t.me")):
        return AppType.TELEGRAM

    # TikTok
    if any(p in lower for p in ("tiktok", "tiktokcdn", "musical.ly", "bytedance")):
        return AppType.TIKTOK

    # Spotify
    if any(p in lower for p in ("spotify", "scdn.co")):
        return AppType.SPOTIFY

    # Zoom
    if "zoom" in lower:
        return AppType.ZOOM

    # Discord
    if any(p in lower for p in ("discord", "discordapp")):
        return AppType.DISCORD

    # GitHub
    if any(p in lower for p in ("github", "githubusercontent")):
        return AppType.GITHUB

    # Cloudflare
    if any(p in lower for p in ("cloudflare", "cf-")):
        return AppType.CLOUDFLARE

    # SNI present but unrecognized — at least it's TLS/HTTPS
    return AppType.HTTPS


def app_name_to_type(name: str) -> Optional[AppType]:
    """Look up an AppType by its display name (case-insensitive)."""
    name_lower = name.lower()
    for app in AppType:
        if app.value.lower() == name_lower:
            return app
    return None
