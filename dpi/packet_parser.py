"""
Network protocol parser.

Extracts fields from raw packet bytes by walking the protocol stack:
  Ethernet (14 B) → IPv4 (20+ B) → TCP (20+ B) / UDP (8 B)

All multi-byte fields are read in network byte order (big-endian) using
Python's ``struct`` module with the ``!`` (network) format character.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional


# =============================================================================
# Protocol Constants
# =============================================================================

# EtherType values
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP  = 0x0806

# IP protocol numbers
PROTO_ICMP = 1
PROTO_TCP  = 6
PROTO_UDP  = 17

# TCP flag bits
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20

# Minimum header sizes
ETH_HEADER_LEN     = 14
MIN_IP_HEADER_LEN  = 20
MIN_TCP_HEADER_LEN = 20
UDP_HEADER_LEN     = 8


# =============================================================================
# Parsed Packet
# =============================================================================

@dataclass
class ParsedPacket:
    """Human-readable representation of a parsed network packet."""

    # Timestamps
    timestamp_sec:  int = 0
    timestamp_usec: int = 0

    # Ethernet layer
    src_mac:    str = ""
    dest_mac:   str = ""
    ether_type: int = 0

    # IP layer
    has_ip:     bool = False
    ip_version: int = 0
    src_ip:     str = ""
    dest_ip:    str = ""
    protocol:   int = 0
    ttl:        int = 0

    # Transport layer
    has_tcp:  bool = False
    has_udp:  bool = False
    src_port: int = 0
    dest_port: int = 0

    # TCP-specific
    tcp_flags:  int = 0
    seq_number: int = 0
    ack_number: int = 0

    # Payload (bounded by the IP total length / UDP length, never by captured bytes
    # or Ethernet padding)
    payload_offset: int = 0
    payload_length: int = 0

    # IPv4 fragmentation: True when MF is set or the fragment offset is non-zero.
    # Such packets are well-formed but cannot be inspected without reassembly
    # (out of scope) -> "unsupported"; no transport fields are parsed for them.
    is_fragment: bool = False


# =============================================================================
# Packet Parser
# =============================================================================

class PacketParser:
    """Stateless parser that extracts protocol fields from raw packet bytes."""

    @staticmethod
    def parse(data: bytes, ts_sec: int = 0, ts_usec: int = 0) -> Optional[ParsedPacket]:
        """
        Parse a raw packet and return a ``ParsedPacket``, or ``None`` if the
        packet is *malformed*.

        Malformed vs unsupported (precedence: structural checks first)
        ---------------------------------------------------------------
        ``None`` (malformed) means header fields are inconsistent with each
        other or with the captured bytes: frame shorter than an Ethernet
        header; IPv4 ethertype but version != 4, IHL < 5, total length < IHL*4,
        or total length larger than the captured bytes (declared bytes missing);
        TCP data offset < 5 or TCP header longer than the IP payload; UDP length
        < 8 or longer than the IP payload.

        A returned packet with ``has_ip`` False, or with ``has_ip`` True but
        neither ``has_tcp`` nor ``has_udp`` (non-TCP/UDP protocol, or an IPv4
        fragment -- ``is_fragment``), is *unsupported*: well-formed as far as we
        parse it, but not something this tool inspects.

        Transport parsing is confined to the declared IP total length; bytes
        beyond it (Ethernet padding) are never treated as payload.  A PCAP
        record whose original length exceeds its captured length is fine as
        long as the IP datagram itself is complete within the captured bytes.
        """
        pkt = ParsedPacket(timestamp_sec=ts_sec, timestamp_usec=ts_usec)
        offset = 0

        # --- Ethernet ---
        if len(data) < ETH_HEADER_LEN:
            return None

        pkt.dest_mac = _mac_to_string(data[0:6])
        pkt.src_mac  = _mac_to_string(data[6:12])
        pkt.ether_type = struct.unpack_from("!H", data, 12)[0]
        offset = ETH_HEADER_LEN

        # --- IPv4 ---
        if pkt.ether_type != ETHERTYPE_IPV4:
            return pkt  # Not IPv4 — unsupported, return what we have

        if len(data) < offset + MIN_IP_HEADER_LEN:
            return None

        version_ihl = data[offset]
        pkt.ip_version = (version_ihl >> 4) & 0x0F
        ihl = version_ihl & 0x0F        # Header length in 32-bit words

        if pkt.ip_version != 4:
            return None

        ip_header_len = ihl * 4
        if ip_header_len < MIN_IP_HEADER_LEN or len(data) < offset + ip_header_len:
            return None

        total_length = struct.unpack_from("!H", data, offset + 2)[0]
        if total_length < ip_header_len:
            return None
        ip_end = offset + total_length
        if ip_end > len(data):
            return None   # datagram declares bytes that were not captured

        flags_frag = struct.unpack_from("!H", data, offset + 6)[0]
        more_fragments = bool(flags_frag & 0x2000)
        fragment_offset = flags_frag & 0x1FFF

        pkt.ttl      = data[offset + 8]
        pkt.protocol = data[offset + 9]

        # Source IP (bytes 12-15 of IP header, network byte order)
        raw_src_ip = data[offset + 12: offset + 16]
        pkt.src_ip = f"{raw_src_ip[0]}.{raw_src_ip[1]}.{raw_src_ip[2]}.{raw_src_ip[3]}"

        # Destination IP (bytes 16-19)
        raw_dst_ip = data[offset + 16: offset + 20]
        pkt.dest_ip = f"{raw_dst_ip[0]}.{raw_dst_ip[1]}.{raw_dst_ip[2]}.{raw_dst_ip[3]}"

        pkt.has_ip = True
        offset += ip_header_len

        if more_fragments or fragment_offset != 0:
            # Well-formed but needs reassembly: unsupported.  Do not read a
            # transport header from fragment payload bytes.
            pkt.is_fragment = True
            pkt.payload_offset = ip_end
            pkt.payload_length = 0
            return pkt

        ip_payload_len = ip_end - offset

        # --- TCP ---
        if pkt.protocol == PROTO_TCP:
            if ip_payload_len < MIN_TCP_HEADER_LEN:
                return None

            pkt.src_port   = struct.unpack_from("!H", data, offset)[0]
            pkt.dest_port  = struct.unpack_from("!H", data, offset + 2)[0]
            pkt.seq_number = struct.unpack_from("!I", data, offset + 4)[0]
            pkt.ack_number = struct.unpack_from("!I", data, offset + 8)[0]

            data_offset = (data[offset + 12] >> 4) & 0x0F
            tcp_header_len = data_offset * 4

            pkt.tcp_flags = data[offset + 13]

            if tcp_header_len < MIN_TCP_HEADER_LEN or tcp_header_len > ip_payload_len:
                return None

            pkt.has_tcp = True
            offset += tcp_header_len
            payload_end = ip_end

        # --- UDP ---
        elif pkt.protocol == PROTO_UDP:
            if ip_payload_len < UDP_HEADER_LEN:
                return None

            pkt.src_port  = struct.unpack_from("!H", data, offset)[0]
            pkt.dest_port = struct.unpack_from("!H", data, offset + 2)[0]
            udp_length    = struct.unpack_from("!H", data, offset + 4)[0]

            if udp_length < UDP_HEADER_LEN or udp_length > ip_payload_len:
                return None

            pkt.has_udp = True
            payload_end = offset + udp_length
            offset += UDP_HEADER_LEN

        else:
            # Other IP protocol: unsupported; nothing more to parse.
            pkt.payload_offset = ip_end
            pkt.payload_length = 0
            return pkt

        # --- Payload (bounded by the declared lengths, not the frame) ---
        pkt.payload_offset = offset
        pkt.payload_length = max(0, payload_end - offset)

        return pkt


# =============================================================================
# Helpers
# =============================================================================

def _mac_to_string(mac_bytes: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac_bytes)


def ip_to_string(ip_bytes: bytes) -> str:
    """Convert 4 raw bytes (network order) to dotted-decimal string."""
    return f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}"


def protocol_to_string(proto: int) -> str:
    return {PROTO_ICMP: "ICMP", PROTO_TCP: "TCP", PROTO_UDP: "UDP"}.get(
        proto, f"Unknown({proto})"
    )


def tcp_flags_to_string(flags: int) -> str:
    names = []
    if flags & TCP_SYN: names.append("SYN")
    if flags & TCP_ACK: names.append("ACK")
    if flags & TCP_FIN: names.append("FIN")
    if flags & TCP_RST: names.append("RST")
    if flags & TCP_PSH: names.append("PSH")
    if flags & TCP_URG: names.append("URG")
    return " ".join(names) if names else "none"
