"""
Review finding 2: network-layer boundary validation.

Malformed (parser returns None): IPv4 header fields inconsistent with each
other or with the captured bytes; TCP/UDP header lengths inconsistent with
the IP payload.  Unsupported (parsed, but no transport): IPv4 fragments and
non-TCP/UDP protocols.  Structural checks take precedence over the
unsupported classification.  Transport parsing is confined to the declared IP
total length, so Ethernet padding is never payload.  A PCAP record whose
orig_len exceeds its captured length is legitimate when the datagram itself is
complete.
"""

import contextlib
import io
import os
import struct
import tempfile
import unittest

from dpi.engine import DPIEngine
from dpi.engine_mt import DPIEngineMT
from dpi.inspection import Outcome, categorize
from dpi.packet_parser import PacketParser

from tests import fixtures as fx

C, S = "192.0.2.10", "198.51.100.5"


def _frame(ip_header: bytes, transport: bytes, pad: bytes = b"") -> bytes:
    return fx.eth() + ip_header + transport + pad


class TestParserBoundaries(unittest.TestCase):
    # --- review reproductions -------------------------------------------------

    def test_ipv4_declares_more_bytes_than_captured_is_malformed(self):
        """IP total length 60, but only 40 IP bytes captured (20 hdr + 20 TCP)."""
        seg = fx.tcp(40000, 443, fx.TCP_SYN)
        data = _frame(fx.ipv4(C, S, fx.PROTO_TCP, len(seg), total_len=60), seg)
        self.assertEqual(len(data), 14 + 40)
        self.assertIsNone(PacketParser.parse(data))
        self.assertIs(categorize(PacketParser.parse(data)), Outcome.MALFORMED)

    def test_udp_length_larger_than_ip_payload_is_malformed(self):
        """UDP header claims 100 bytes inside a 28-byte IP datagram."""
        dgram = fx.udp(50000, 53, 0, length=100)
        data = _frame(fx.ipv4(C, S, fx.PROTO_UDP, len(dgram)), dgram)
        self.assertIsNone(PacketParser.parse(data))

    def test_non_first_fragment_is_unsupported_not_tcp(self):
        """Fragment payload that looks like a TCP header to port 443 must not become a TCP flow."""
        fake_tcp = fx.tcp(40000, 443, fx.TCP_SYN)
        hdr = fx.ipv4(C, S, fx.PROTO_TCP, len(fake_tcp), flags_frag=0x0000 | 185)   # offset 185*8
        pkt = PacketParser.parse(_frame(hdr, fake_tcp))
        self.assertIsNotNone(pkt)
        self.assertTrue(pkt.has_ip)
        self.assertTrue(pkt.is_fragment)
        self.assertFalse(pkt.has_tcp)
        self.assertEqual(pkt.dest_port, 0)
        self.assertEqual(pkt.payload_length, 0)
        self.assertIs(categorize(pkt), Outcome.UNSUPPORTED)

    def test_first_fragment_with_more_fragments_is_unsupported(self):
        seg = fx.tcp(40000, 443, fx.TCP_SYN) + b"x" * 8
        hdr = fx.ipv4(C, S, fx.PROTO_TCP, len(seg), flags_frag=fx.IP_FLAG_MF)
        pkt = PacketParser.parse(_frame(hdr, seg))
        self.assertTrue(pkt.is_fragment)
        self.assertFalse(pkt.has_tcp)
        self.assertIs(categorize(pkt), Outcome.UNSUPPORTED)

    # --- precedence and other structural checks --------------------------------

    def test_malformed_takes_precedence_over_fragment(self):
        seg = fx.tcp(40000, 443, fx.TCP_SYN)
        hdr = fx.ipv4(C, S, fx.PROTO_TCP, len(seg), flags_frag=fx.IP_FLAG_MF, total_len=200)
        self.assertIsNone(PacketParser.parse(_frame(hdr, seg)))

    def test_bad_version_and_ihl(self):
        seg = fx.tcp(40000, 443, fx.TCP_SYN)
        self.assertIsNone(PacketParser.parse(_frame(fx.ipv4(C, S, 6, len(seg), version_ihl=0x65), seg)))
        self.assertIsNone(PacketParser.parse(_frame(fx.ipv4(C, S, 6, len(seg), version_ihl=0x44), seg)))
        # IHL 6 (24-byte header) claimed but total length says 20: inconsistent
        self.assertIsNone(PacketParser.parse(_frame(fx.ipv4(C, S, 6, len(seg), version_ihl=0x46, total_len=20), seg)))

    def test_total_length_smaller_than_header(self):
        seg = fx.tcp(40000, 443, fx.TCP_SYN)
        self.assertIsNone(PacketParser.parse(_frame(fx.ipv4(C, S, 6, len(seg), total_len=19), seg)))

    def test_tcp_header_length_checks(self):
        seg = fx.tcp(40000, 443, fx.TCP_SYN, data_offset=4)           # < 20 bytes
        self.assertIsNone(PacketParser.parse(_frame(fx.ipv4(C, S, 6, len(seg)), seg)))
        seg = fx.tcp(40000, 443, fx.TCP_SYN, data_offset=15)          # 60 bytes > 20-byte IP payload
        self.assertIsNone(PacketParser.parse(_frame(fx.ipv4(C, S, 6, len(seg)), seg)))
        seg = fx.tcp(40000, 443, fx.TCP_SYN)[:16]                     # IP payload shorter than TCP header
        self.assertIsNone(PacketParser.parse(_frame(fx.ipv4(C, S, 6, len(seg)), seg)))

    def test_udp_length_checks(self):
        dgram = fx.udp(50000, 53, 0, length=7)
        self.assertIsNone(PacketParser.parse(_frame(fx.ipv4(C, S, 17, len(dgram)), dgram)))
        dgram = fx.udp(50000, 53, 0)[:6]
        self.assertIsNone(PacketParser.parse(_frame(fx.ipv4(C, S, 17, len(dgram)), dgram)))

    def test_other_ip_protocol_is_unsupported(self):
        pkt = PacketParser.parse(fx.icmp_packet())
        self.assertTrue(pkt.has_ip)
        self.assertFalse(pkt.has_tcp or pkt.has_udp)
        self.assertIs(categorize(pkt), Outcome.UNSUPPORTED)

    # --- padding and legitimate snaplen records ---------------------------------

    def test_ethernet_padding_is_not_payload(self):
        seg = fx.tcp(40000, 443, fx.TCP_SYN)
        data = _frame(fx.ipv4(C, S, 6, len(seg)), seg, pad=b"\x16\x03\x01" * 4)   # TLS-looking padding
        pkt = PacketParser.parse(data)
        self.assertTrue(pkt.has_tcp)
        self.assertEqual(pkt.payload_length, 0)

    def test_udp_payload_bounded_by_udp_length(self):
        payload = b"A" * 20
        dgram = fx.udp(50000, 53, len(payload), length=8 + 5) + payload   # declares 5 payload bytes
        data = _frame(fx.ipv4(C, S, 17, len(dgram)), dgram)
        pkt = PacketParser.parse(data)
        self.assertTrue(pkt.has_udp)
        self.assertEqual(pkt.payload_length, 5)

    def test_tcp_payload_bounded_by_ip_total_length(self):
        payload = b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n"
        seg = fx.tcp(40000, 80, fx.TCP_PSH | fx.TCP_ACK) + payload
        data = _frame(fx.ipv4(C, S, 6, len(seg)), seg, pad=b"\r\nHost: evil.test\r\n")
        pkt = PacketParser.parse(data)
        self.assertEqual(data[pkt.payload_offset: pkt.payload_offset + pkt.payload_length], payload)

    def test_orig_len_greater_than_captured_is_not_malformed(self):
        """A 60-byte wire frame captured as 54 bytes is fine when the IP datagram is complete."""
        seg = fx.tcp(40000, 443, fx.TCP_SYN)
        data = _frame(fx.ipv4(C, S, 6, len(seg)), seg)          # 54 bytes, IP total 40
        self.assertEqual(len(data), 54)
        self.assertIsNotNone(PacketParser.parse(data))
        self.assertIsNone(categorize(PacketParser.parse(data)))


class TestEngineBoundaryAccounting(unittest.TestCase):
    """The review's three reproductions through both engines with a port-443 rule."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.dir.cleanup()

    def _packets(self):
        seg = fx.tcp(40000, 443, fx.TCP_SYN)
        truncated_ip = _frame(fx.ipv4(C, S, 6, len(seg), total_len=60), seg)
        dgram = fx.udp(50000, 53, 0, length=100)
        bad_udp = _frame(fx.ipv4(C, S, 17, len(dgram)), dgram)
        fake_tcp = fx.tcp(40001, 443, fx.TCP_SYN)
        fragment = _frame(fx.ipv4(C, S, 6, len(fake_tcp), flags_frag=185), fake_tcp)
        first_frag = _frame(fx.ipv4(C, S, 6, len(seg), flags_frag=fx.IP_FLAG_MF), seg)
        good = fx.tcp_packet(C, S, 40002, 8080, fx.TCP_SYN)
        return [good, truncated_ip, bad_udp, fragment, first_frag, good]

    def test_both_engines_exclude_and_account(self):
        in_path = os.path.join(self.dir.name, "in.pcap")
        fx.write_pcap(in_path, self._packets())
        for label, make in (("simple", DPIEngine), ("mt", lambda: DPIEngineMT(2, 2))):
            with self.subTest(engine=label):
                eng = make()
                eng.block_port(443)
                out = os.path.join(self.dir.name, f"{label}.pcap")
                with contextlib.redirect_stdout(io.StringIO()):
                    eng.process_file(in_path, out)
                s = eng.stats
                self.assertEqual(s.total_packets, 6)
                self.assertEqual(s.malformed_packets, 2)      # truncated IP, oversized UDP
                self.assertEqual(s.unsupported_packets, 2)    # both fragments
                self.assertEqual(s.dropped_packets, 0, "fragment bytes must not match a port rule")
                self.assertEqual(s.forwarded_packets, 2)
                self.assertTrue(s.reconciles())
                good = fx.tcp_packet(C, S, 40002, 8080, fx.TCP_SYN)
                self.assertEqual(fx.read_pcap(out), [good, good])
                self.assertEqual(eng.flow_count, 1)

    def test_snapped_record_is_retained_with_metadata(self):
        seg = fx.tcp(40000, 443, fx.TCP_SYN)
        data = _frame(fx.ipv4(C, S, 6, len(seg)), seg)
        in_path = os.path.join(self.dir.name, "in.pcap")
        fx.write_pcap_records(in_path, [(123, 456789, data, 60)])
        for label, make in (("simple", DPIEngine), ("mt", lambda: DPIEngineMT(1, 2))):
            with self.subTest(engine=label):
                eng = make()
                out = os.path.join(self.dir.name, f"{label}.pcap")
                with contextlib.redirect_stdout(io.StringIO()):
                    eng.process_file(in_path, out)
                self.assertEqual(eng.stats.forwarded_packets, 1)
                self.assertEqual(eng.stats.malformed_packets, 0)


if __name__ == "__main__":
    unittest.main()
