"""
Unit tests for dpi.sni_extractor module.

Tests TLS SNI, HTTP Host, and DNS query extraction from raw payloads.
"""

import struct
import unittest

from dpi.sni_extractor import SNIExtractor, HTTPHostExtractor, DNSExtractor


class TestSNIExtractor(unittest.TestCase):
    """Test TLS Client Hello SNI extraction."""

    @staticmethod
    def _build_tls_client_hello(sni: str) -> bytes:
        """Build a minimal TLS Client Hello with an SNI extension."""
        sni_bytes = sni.encode("ascii")

        # SNI extension (type 0x0000)
        sni_entry = struct.pack("!BH", 0, len(sni_bytes)) + sni_bytes
        sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
        sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

        # Extensions block
        extensions = struct.pack("!H", len(sni_ext)) + sni_ext

        # Client Hello body
        body = (
            struct.pack("!H", 0x0303)             # Version TLS 1.2
            + bytes(32)                             # Random
            + struct.pack("B", 0)                   # Session ID length
            + struct.pack("!H", 2)                  # Cipher suites length
            + struct.pack("!H", 0x1301)             # TLS_AES_128_GCM
            + struct.pack("BB", 1, 0)               # Compression
            + extensions
        )

        # Handshake header
        handshake = struct.pack("B", 0x01)  # ClientHello
        handshake += struct.pack("!I", len(body))[1:]  # 3-byte length
        handshake += body

        # TLS record
        record = struct.pack("B", 0x16)              # Handshake
        record += struct.pack("!H", 0x0301)           # TLS 1.0
        record += struct.pack("!H", len(handshake))
        record += handshake

        return record

    def test_extract_sni(self):
        payload = self._build_tls_client_hello("www.example.com")
        result = SNIExtractor.extract(payload)
        self.assertEqual(result, "www.example.com")

    def test_extract_youtube_sni(self):
        payload = self._build_tls_client_hello("www.youtube.com")
        result = SNIExtractor.extract(payload)
        self.assertEqual(result, "www.youtube.com")

    def test_extract_long_sni(self):
        payload = self._build_tls_client_hello("subdomain.deep.nested.example.co.uk")
        result = SNIExtractor.extract(payload)
        self.assertEqual(result, "subdomain.deep.nested.example.co.uk")

    def test_not_tls(self):
        self.assertIsNone(SNIExtractor.extract(b"\x00\x01\x02\x03"))

    def test_empty_payload(self):
        self.assertIsNone(SNIExtractor.extract(b""))

    def test_truncated_tls(self):
        payload = self._build_tls_client_hello("test.com")
        truncated = payload[:20]
        self.assertIsNone(SNIExtractor.extract(truncated))

    def test_is_tls_client_hello(self):
        payload = self._build_tls_client_hello("test.com")
        self.assertTrue(SNIExtractor.is_tls_client_hello(payload))
        self.assertFalse(SNIExtractor.is_tls_client_hello(b"GET / HTTP/1.1"))


class TestHTTPHostExtractor(unittest.TestCase):
    """Test HTTP Host header extraction."""

    def test_extract_host(self):
        payload = b"GET / HTTP/1.1\r\nHost: www.example.com\r\nAccept: */*\r\n\r\n"
        result = HTTPHostExtractor.extract(payload)
        self.assertEqual(result, "www.example.com")

    def test_extract_host_with_port(self):
        payload = b"GET / HTTP/1.1\r\nHost: www.example.com:8080\r\n\r\n"
        result = HTTPHostExtractor.extract(payload)
        self.assertEqual(result, "www.example.com")

    def test_extract_post(self):
        payload = b"POST /api HTTP/1.1\r\nHost: api.server.com\r\n\r\n"
        result = HTTPHostExtractor.extract(payload)
        self.assertEqual(result, "api.server.com")

    def test_case_insensitive_host(self):
        payload = b"GET / HTTP/1.1\r\nHOST: UPPER.COM\r\n\r\n"
        result = HTTPHostExtractor.extract(payload)
        self.assertEqual(result, "UPPER.COM")

    def test_not_http(self):
        self.assertIsNone(HTTPHostExtractor.extract(b"\x16\x03\x01\x00"))

    def test_no_host_header(self):
        payload = b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n"
        self.assertIsNone(HTTPHostExtractor.extract(payload))

    def test_is_http_request(self):
        self.assertTrue(HTTPHostExtractor.is_http_request(b"GET / HTTP/1.1"))
        self.assertTrue(HTTPHostExtractor.is_http_request(b"POST /api HTTP/1.1"))
        self.assertFalse(HTTPHostExtractor.is_http_request(b"\x16\x03\x01"))


class TestDNSExtractor(unittest.TestCase):
    """Test DNS query domain extraction."""

    @staticmethod
    def _build_dns_query(domain: str) -> bytes:
        """Build a minimal DNS query payload."""
        txid = struct.pack("!H", 0x1234)
        flags = struct.pack("!H", 0x0100)  # Standard query
        counts = struct.pack("!HHHH", 1, 0, 0, 0)

        question = b""
        for label in domain.split("."):
            question += struct.pack("B", len(label)) + label.encode()
        question += struct.pack("B", 0)  # Null terminator
        question += struct.pack("!HH", 1, 1)  # Type A, Class IN

        return txid + flags + counts + question

    def test_extract_domain(self):
        payload = self._build_dns_query("www.google.com")
        result = DNSExtractor.extract_query(payload)
        self.assertEqual(result, "www.google.com")

    def test_extract_subdomain(self):
        payload = self._build_dns_query("api.v2.service.example.com")
        result = DNSExtractor.extract_query(payload)
        self.assertEqual(result, "api.v2.service.example.com")

    def test_not_dns(self):
        self.assertIsNone(DNSExtractor.extract_query(b"\x00\x01\x02"))

    def test_empty_payload(self):
        self.assertIsNone(DNSExtractor.extract_query(b""))

    def test_is_dns_query(self):
        payload = self._build_dns_query("test.com")
        self.assertTrue(DNSExtractor.is_dns_query(payload))
        self.assertFalse(DNSExtractor.is_dns_query(b"GET / HTTP"))


if __name__ == "__main__":
    unittest.main()
