"""
Review finding 4: incomplete or malformed TLS / DNS / HTTP application data must
never produce a positive name or a domain-rule match.

Fixtures are assembled independently with ``struct`` in this file (they are
deliberately *not* built with the extractor's own helpers).  Valid boundary
cases must still be extracted; the review's two reproductions must not.

Accounting / retention policy (documented in docs/USAGE.md): an unparseable
application payload does not change the packet's category.  The packet is a
structurally valid TCP/UDP packet, so it is retained (or filtered by IP/port/
app rules) and its flow simply has no observed name -- the flow's class stays
at the port heuristic (HTTPS / HTTP / DNS).  Only transport-level structural
faults make a packet *malformed*; only non-IPv4-TCP/UDP makes it *unsupported*.
"""

import contextlib
import io
import os
import struct
import tempfile
import unittest

from dpi.engine import DPIEngine
from dpi.engine_mt import DPIEngineMT
from dpi.sni_extractor import DNSExtractor, HTTPHostExtractor, SNIExtractor

from tests import fixtures as fx


# --- independent TLS builders -------------------------------------------------

def _sni_ext(name: bytes, entry_type: int = 0, list_len=None, name_len=None) -> bytes:
    entry = struct.pack("!BH", entry_type, len(name) if name_len is None else name_len) + name
    lst = struct.pack("!H", len(entry) if list_len is None else list_len) + entry
    return struct.pack("!HH", 0x0000, len(lst)) + lst


def _client_hello_body(extensions: bytes, ext_len=None) -> bytes:
    return (struct.pack("!H", 0x0303) + bytes(32) + b"\x00"
            + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
            + struct.pack("!H", len(extensions) if ext_len is None else ext_len) + extensions)


def _handshake(body: bytes, hs_len=None) -> bytes:
    n = len(body) if hs_len is None else hs_len
    return b"\x01" + n.to_bytes(3, "big") + body


def _record(handshake: bytes, record_len=None) -> bytes:
    n = len(handshake) if record_len is None else record_len
    return b"\x16\x03\x01" + struct.pack("!H", n) + handshake


def _valid_hello(name: str = "blocked.example") -> bytes:
    return _record(_handshake(_client_hello_body(_sni_ext(name.encode()))))


# --- independent DNS builders -------------------------------------------------

def _dns_header(qd: int = 1) -> bytes:
    return struct.pack("!HHHHHH", 0x1234, 0x0100, qd, 0, 0, 0)


def _qname(*labels: bytes) -> bytes:
    return b"".join(bytes([len(l)]) + l for l in labels) + b"\x00"


class TestTLSBounds(unittest.TestCase):
    def test_valid_hello_extracts(self):
        self.assertEqual(SNIExtractor.extract(_valid_hello()), "blocked.example")

    def test_review_repro_record_declares_only_handshake_header(self):
        """Record length says 4 bytes; a full Client Hello follows anyway.  Must not extract."""
        full = _handshake(_client_hello_body(_sni_ext(b"blocked.example")))
        payload = _record(full, record_len=4)
        self.assertIsNone(SNIExtractor.extract(payload))

    def test_handshake_length_shorter_than_body(self):
        body = _client_hello_body(_sni_ext(b"blocked.example"))
        self.assertIsNone(SNIExtractor.extract(_record(_handshake(body, hs_len=10))))

    def test_handshake_length_longer_than_record(self):
        body = _client_hello_body(_sni_ext(b"blocked.example"))
        self.assertIsNone(SNIExtractor.extract(_record(_handshake(body, hs_len=len(body) + 50))))

    def test_extensions_length_overruns_body(self):
        body = _client_hello_body(_sni_ext(b"blocked.example"), ext_len=500)
        self.assertIsNone(SNIExtractor.extract(_record(_handshake(body))))

    def test_extensions_length_shorter_than_sni_extension(self):
        ext = _sni_ext(b"blocked.example")
        body = _client_hello_body(ext, ext_len=len(ext) - 3)
        self.assertIsNone(SNIExtractor.extract(_record(_handshake(body))))

    def test_sni_list_length_overruns_extension(self):
        body = _client_hello_body(_sni_ext(b"blocked.example", list_len=200))
        self.assertIsNone(SNIExtractor.extract(_record(_handshake(body))))

    def test_sni_name_length_overruns_list(self):
        body = _client_hello_body(_sni_ext(b"blocked.example", name_len=100))
        self.assertIsNone(SNIExtractor.extract(_record(_handshake(body))))

    def test_truncated_record_is_rejected_not_partially_parsed(self):
        payload = _valid_hello()
        for cut in (len(payload) - 1, len(payload) - 8, 60, 45):
            self.assertIsNone(SNIExtractor.extract(payload[:cut]), cut)

    def test_trailing_bytes_after_record_are_ignored(self):
        """A complete record followed by junk still yields the record's own name only."""
        self.assertEqual(SNIExtractor.extract(_valid_hello("ok.example") + b"\x16\x03\x01" * 5), "ok.example")

    def test_non_hostname_entry_type_is_not_a_name(self):
        body = _client_hello_body(_sni_ext(b"blocked.example", entry_type=1))
        self.assertIsNone(SNIExtractor.extract(_record(_handshake(body))))

    def test_empty_overlong_and_non_ascii_names_rejected(self):
        self.assertIsNone(SNIExtractor.extract(_record(_handshake(_client_hello_body(_sni_ext(b""))))))
        self.assertIsNone(SNIExtractor.extract(_record(_handshake(_client_hello_body(_sni_ext(b"a" * 256))))))
        self.assertIsNone(SNIExtractor.extract(_record(_handshake(_client_hello_body(_sni_ext(b"\xff\xfe.x"))))))
        self.assertEqual(len(SNIExtractor.extract(_record(_handshake(_client_hello_body(_sni_ext(b"a" * 255)))))), 255)

    def test_sni_after_another_extension(self):
        other = struct.pack("!HH", 0x002B, 3) + b"\x02\x03\x04"
        body = _client_hello_body(other + _sni_ext(b"second.example"))
        self.assertEqual(SNIExtractor.extract(_record(_handshake(body))), "second.example")


class TestDNSBounds(unittest.TestCase):
    def test_valid_query_extracts(self):
        q = _dns_header() + _qname(b"www", b"example", b"test") + struct.pack("!HH", 1, 1)
        self.assertEqual(DNSExtractor.extract_query(q), "www.example.test")

    def test_review_repro_single_unterminated_label(self):
        """Question is just '\\x03www' -- no terminator, QTYPE or QCLASS.  Must not yield 'www'."""
        self.assertIsNone(DNSExtractor.extract_query(_dns_header() + b"\x03www"))

    def test_missing_terminator(self):
        self.assertIsNone(DNSExtractor.extract_query(_dns_header() + b"\x03www\x07example"))

    def test_terminator_but_missing_qtype_qclass(self):
        q = _dns_header() + _qname(b"www", b"example") 
        self.assertIsNone(DNSExtractor.extract_query(q))
        self.assertIsNone(DNSExtractor.extract_query(q + b"\x00\x01"))        # only QTYPE
        self.assertEqual(DNSExtractor.extract_query(q + b"\x00\x01\x00\x01"), "www.example")

    def test_label_cut_short(self):
        self.assertIsNone(DNSExtractor.extract_query(_dns_header() + b"\x07examp"))

    def test_compression_pointer_rejected_explicitly(self):
        q = _dns_header() + b"\x03www\xc0\x0c" + struct.pack("!HH", 1, 1)
        self.assertIsNone(DNSExtractor.extract_query(q))

    def test_invalid_label_type_rejected(self):
        q = _dns_header() + b"\x03www\x45abc\x00" + struct.pack("!HH", 1, 1)
        self.assertIsNone(DNSExtractor.extract_query(q))

    def test_root_name_and_non_ascii_rejected(self):
        self.assertIsNone(DNSExtractor.extract_query(_dns_header() + b"\x00" + struct.pack("!HH", 1, 1)))
        self.assertIsNone(DNSExtractor.extract_query(_dns_header() + _qname(b"\xff\xfe") + struct.pack("!HH", 1, 1)))

    def test_name_length_limit(self):
        labels = [b"a" * 63] * 3 + [b"b" * 61]           # 63*3+61 + 3 dots = 253 chars: allowed
        q = _dns_header() + _qname(*labels) + struct.pack("!HH", 1, 1)
        self.assertEqual(len(DNSExtractor.extract_query(q)), 253)
        labels = [b"a" * 63] * 3 + [b"b" * 62]           # 254 chars: rejected
        q = _dns_header() + _qname(*labels) + struct.pack("!HH", 1, 1)
        self.assertIsNone(DNSExtractor.extract_query(q))

    def test_response_and_zero_qdcount_rejected(self):
        q = _qname(b"www", b"example") + struct.pack("!HH", 1, 1)
        self.assertIsNone(DNSExtractor.extract_query(struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0) + q))
        self.assertIsNone(DNSExtractor.extract_query(_dns_header(qd=0) + q))


class TestHTTPHostBounds(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(HTTPHostExtractor.extract(b"GET / HTTP/1.1\r\nHost: a.test:8080\r\n\r\n"), "a.test")

    def test_overlong_or_non_ascii_host_rejected(self):
        self.assertIsNone(HTTPHostExtractor.extract(b"GET / HTTP/1.1\r\nHost: " + b"a" * 300 + b"\r\n\r\n"))
        self.assertIsNone(HTTPHostExtractor.extract(b"GET / HTTP/1.1\r\nHost: \xff\xfe.test\r\n\r\n"))
        self.assertIsNone(HTTPHostExtractor.extract(b"GET / HTTP/1.1\r\nHost:   \r\n\r\n"))


class TestEnginePolicy(unittest.TestCase):
    """The review's packets through both engines with a domain rule for the would-be name."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.dir.cleanup()

    def test_malformed_app_data_is_retained_without_name_and_not_filtered(self):
        bad_tls = fx.tcp_packet(fx.CLIENT, "10.4.0.1", 40000, 443, fx.TCP_PSH | fx.TCP_ACK,
                                _record(_handshake(_client_hello_body(_sni_ext(b"blocked.example"))), record_len=4))
        bad_dns = fx.udp_packet(fx.CLIENT, "10.4.0.53", 40001, 53, _dns_header() + b"\x03www")
        good_tls = fx.tcp_packet(fx.CLIENT, "10.4.0.2", 40002, 443, fx.TCP_PSH | fx.TCP_ACK, _valid_hello("blocked.example"))
        in_path = os.path.join(self.dir.name, "in.pcap")
        fx.write_pcap(in_path, [bad_tls, bad_dns, good_tls])
        for label, make in (("simple", DPIEngine), ("mt", lambda: DPIEngineMT(2, 2))):
            with self.subTest(engine=label):
                eng = make()
                eng.block_domain("blocked.example")
                eng.block_domain("www")
                out = os.path.join(self.dir.name, f"{label}.pcap")
                with contextlib.redirect_stdout(io.StringIO()):
                    eng.process_file(in_path, out)
                s = eng.stats
                self.assertEqual((s.total_packets, s.malformed_packets, s.unsupported_packets), (3, 0, 0))
                self.assertEqual(s.dropped_packets, 1, "only the well-formed Client Hello matches")
                self.assertEqual(s.forwarded_packets, 2)
                self.assertEqual(fx.read_pcap(out), [bad_tls, bad_dns])
                names = {c.tls_sni or c.dns_query for c in eng.connections()}
                self.assertEqual(names, {"", "blocked.example"})
                by_class = sorted(c.app_type.value for c in eng.connections())
                self.assertEqual(by_class, ["DNS", "HTTPS", "HTTPS"])   # port heuristics only for the bad two


if __name__ == "__main__":
    unittest.main()
