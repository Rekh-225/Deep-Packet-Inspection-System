"""
Unit tests for dpi.packet_parser module.

Tests protocol header parsing for Ethernet, IPv4, TCP, and UDP.
"""

import struct
import unittest

from dpi.packet_parser import (
    PacketParser,
    ParsedPacket,
    ETH_HEADER_LEN,
    ETHERTYPE_IPV4,
    PROTO_TCP,
    PROTO_UDP,
    TCP_SYN,
    TCP_ACK,
    tcp_flags_to_string,
    protocol_to_string,
)


def _build_eth_header(ether_type=ETHERTYPE_IPV4):
    """Build a minimal Ethernet header."""
    dst_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
    src_mac = b"\x00\x11\x22\x33\x44\x55"
    return dst_mac + src_mac + struct.pack("!H", ether_type)


def _build_ip_header(src_ip, dst_ip, protocol=PROTO_TCP, payload_len=20):
    """Build a minimal IPv4 header (20 bytes, no options)."""
    version_ihl = 0x45
    tos = 0
    total_len = 20 + payload_len
    ident = 0x1234
    flags_frag = 0x4000
    ttl = 64
    checksum = 0

    header = struct.pack(
        "!BBHHHBBH",
        version_ihl, tos, total_len,
        ident, flags_frag,
        ttl, protocol, checksum,
    )
    header += bytes(int(x) for x in src_ip.split("."))
    header += bytes(int(x) for x in dst_ip.split("."))
    return header


def _build_tcp_header(src_port=12345, dst_port=443, flags=TCP_SYN):
    """Build a minimal TCP header (20 bytes)."""
    seq = 1000
    ack = 0
    data_offset = 5 << 4  # 20 bytes
    window = 65535
    checksum = 0
    urgent = 0
    return struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack,
        data_offset, flags, window, checksum, urgent,
    )


def _build_udp_header(src_port=54321, dst_port=53, payload_len=0):
    """Build a UDP header (8 bytes)."""
    length = 8 + payload_len
    checksum = 0
    return struct.pack("!HHHH", src_port, dst_port, length, checksum)


class TestPacketParser(unittest.TestCase):
    """Test PacketParser.parse()."""

    def test_parse_tcp_packet(self):
        data = (
            _build_eth_header()
            + _build_ip_header("192.168.1.100", "10.0.0.1", PROTO_TCP, 20)
            + _build_tcp_header(12345, 443, TCP_SYN)
        )
        pkt = PacketParser.parse(data)
        self.assertIsNotNone(pkt)
        self.assertTrue(pkt.has_ip)
        self.assertTrue(pkt.has_tcp)
        self.assertFalse(pkt.has_udp)
        self.assertEqual(pkt.src_ip, "192.168.1.100")
        self.assertEqual(pkt.dest_ip, "10.0.0.1")
        self.assertEqual(pkt.src_port, 12345)
        self.assertEqual(pkt.dest_port, 443)
        self.assertEqual(pkt.protocol, PROTO_TCP)
        self.assertEqual(pkt.tcp_flags & TCP_SYN, TCP_SYN)

    def test_parse_udp_packet(self):
        dns_payload = b"\x00" * 12  # Minimal DNS stub
        data = (
            _build_eth_header()
            + _build_ip_header("192.168.1.100", "8.8.8.8", PROTO_UDP, 8 + len(dns_payload))
            + _build_udp_header(54321, 53, len(dns_payload))
            + dns_payload
        )
        pkt = PacketParser.parse(data)
        self.assertIsNotNone(pkt)
        self.assertTrue(pkt.has_ip)
        self.assertFalse(pkt.has_tcp)
        self.assertTrue(pkt.has_udp)
        self.assertEqual(pkt.src_port, 54321)
        self.assertEqual(pkt.dest_port, 53)
        self.assertEqual(pkt.protocol, PROTO_UDP)
        self.assertGreater(pkt.payload_length, 0)

    def test_parse_non_ip(self):
        """Non-IPv4 EtherType should return a packet but with has_ip=False."""
        data = _build_eth_header(ether_type=0x0806)  # ARP
        data += b"\x00" * 28  # ARP body stub
        pkt = PacketParser.parse(data)
        self.assertIsNotNone(pkt)
        self.assertFalse(pkt.has_ip)

    def test_parse_too_short(self):
        """Too-short data should return None."""
        self.assertIsNone(PacketParser.parse(b"\x00" * 5))

    def test_payload_offset(self):
        """Payload offset should point past all headers."""
        payload = b"HELLO_PAYLOAD"
        data = (
            _build_eth_header()
            + _build_ip_header("10.0.0.1", "10.0.0.2", PROTO_TCP, 20 + len(payload))
            + _build_tcp_header(80, 12345, TCP_ACK)
            + payload
        )
        pkt = PacketParser.parse(data)
        self.assertIsNotNone(pkt)
        self.assertEqual(pkt.payload_length, len(payload))
        self.assertEqual(data[pkt.payload_offset:], payload)


class TestHelperFunctions(unittest.TestCase):

    def test_tcp_flags_to_string(self):
        self.assertIn("SYN", tcp_flags_to_string(TCP_SYN))
        self.assertIn("ACK", tcp_flags_to_string(TCP_ACK))
        self.assertIn("SYN", tcp_flags_to_string(TCP_SYN | TCP_ACK))
        self.assertIn("ACK", tcp_flags_to_string(TCP_SYN | TCP_ACK))
        self.assertEqual(tcp_flags_to_string(0), "none")

    def test_protocol_to_string(self):
        self.assertEqual(protocol_to_string(6), "TCP")
        self.assertEqual(protocol_to_string(17), "UDP")
        self.assertIn("Unknown", protocol_to_string(99))


if __name__ == "__main__":
    unittest.main()
