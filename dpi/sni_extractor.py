"""
Deep Packet Inspection extractors.

Extracts application-layer identifiers from packet payloads:
  - TLS Client Hello → SNI (Server Name Indication)
  - HTTP request → Host header
  - DNS query → queried domain name
  - QUIC Initial → embedded TLS Client Hello SNI

All extractors return ``None`` when the payload doesn't match the expected
protocol format, allowing callers to try multiple extractors in sequence.
"""

from __future__ import annotations

import struct
from typing import Optional


# =============================================================================
# TLS Constants
# =============================================================================

_CONTENT_TYPE_HANDSHAKE   = 0x16
_HANDSHAKE_CLIENT_HELLO   = 0x01
_EXTENSION_SNI            = 0x0000
_SNI_TYPE_HOSTNAME        = 0x00


# =============================================================================
# TLS SNI Extractor
# =============================================================================

class SNIExtractor:
    """Extract Server Name Indication from a TLS Client Hello payload."""

    @staticmethod
    def is_tls_client_hello(payload: bytes) -> bool:
        """Return True if *payload* looks like a TLS Client Hello."""
        if len(payload) < 9:
            return False
        # Content type = Handshake (0x16)
        if payload[0] != _CONTENT_TYPE_HANDSHAKE:
            return False
        # TLS version 0x0300..0x0304
        version = struct.unpack_from("!H", payload, 1)[0]
        if version < 0x0300 or version > 0x0304:
            return False
        # Record length
        record_len = struct.unpack_from("!H", payload, 3)[0]
        if record_len > len(payload) - 5:
            return False
        # Handshake type = Client Hello (0x01)
        if payload[5] != _HANDSHAKE_CLIENT_HELLO:
            return False
        return True

    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        """
        Extract the SNI hostname from a TLS Client Hello.

        Returns the hostname string, or ``None`` if not found.
        """
        if not SNIExtractor.is_tls_client_hello(payload):
            return None

        try:
            offset = 5  # Skip TLS record header

            # Handshake header: type (1) + length (3)
            offset += 4

            # Client Hello body: version (2) + random (32)
            offset += 2 + 32

            # Session ID
            if offset >= len(payload):
                return None
            session_id_len = payload[offset]
            offset += 1 + session_id_len

            # Cipher suites
            if offset + 2 > len(payload):
                return None
            cipher_suites_len = struct.unpack_from("!H", payload, offset)[0]
            offset += 2 + cipher_suites_len

            # Compression methods
            if offset >= len(payload):
                return None
            comp_len = payload[offset]
            offset += 1 + comp_len

            # Extensions
            if offset + 2 > len(payload):
                return None
            extensions_len = struct.unpack_from("!H", payload, offset)[0]
            offset += 2

            extensions_end = min(offset + extensions_len, len(payload))

            # Walk extensions looking for SNI (type 0x0000)
            while offset + 4 <= extensions_end:
                ext_type = struct.unpack_from("!H", payload, offset)[0]
                ext_len  = struct.unpack_from("!H", payload, offset + 2)[0]
                offset += 4

                if offset + ext_len > extensions_end:
                    break

                if ext_type == _EXTENSION_SNI:
                    # SNI extension structure:
                    #   list_length (2) + type (1) + name_length (2) + name
                    if ext_len < 5:
                        break
                    sni_type = payload[offset + 2]
                    sni_len  = struct.unpack_from("!H", payload, offset + 3)[0]
                    if sni_type != _SNI_TYPE_HOSTNAME:
                        break
                    if sni_len > ext_len - 5:
                        break
                    return payload[offset + 5: offset + 5 + sni_len].decode("ascii", errors="replace")

                offset += ext_len

        except (struct.error, IndexError):
            pass

        return None


# =============================================================================
# HTTP Host Extractor
# =============================================================================

class HTTPHostExtractor:
    """Extract the Host header from an HTTP request."""

    _HTTP_METHODS = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")

    @staticmethod
    def is_http_request(payload: bytes) -> bool:
        if len(payload) < 4:
            return False
        return any(payload[:4] == m for m in HTTPHostExtractor._HTTP_METHODS)

    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        """Extract the ``Host`` header value from an HTTP request."""
        if not HTTPHostExtractor.is_http_request(payload):
            return None

        # Search for "Host:" (case-insensitive)
        lower = payload.lower()
        markers = (b"\r\nhost:", b"\nhost:")
        for marker in markers:
            idx = lower.find(marker)
            if idx == -1:
                continue

            # Skip past "Host:" and whitespace
            start = idx + len(marker)
            while start < len(payload) and payload[start:start+1] in (b" ", b"\t"):
                start += 1

            # Find end of line
            end = start
            while end < len(payload) and payload[end:end+1] not in (b"\r", b"\n"):
                end += 1

            if end > start:
                host = payload[start:end].decode("ascii", errors="replace").strip()
                # Remove port if present
                if ":" in host:
                    host = host.split(":")[0]
                return host

        return None


# =============================================================================
# DNS Query Extractor
# =============================================================================

class DNSExtractor:
    """Extract the queried domain name from a DNS query."""

    @staticmethod
    def is_dns_query(payload: bytes) -> bool:
        if len(payload) < 12:
            return False
        # QR bit (byte 2, bit 7) must be 0 for a query
        if payload[2] & 0x80:
            return False
        # QDCOUNT > 0
        qdcount = struct.unpack_from("!H", payload, 4)[0]
        return qdcount > 0

    @staticmethod
    def extract_query(payload: bytes) -> Optional[str]:
        """Extract the queried domain name from a DNS query payload."""
        if not DNSExtractor.is_dns_query(payload):
            return None

        offset = 12  # Skip DNS header
        labels: list[str] = []

        try:
            while offset < len(payload):
                label_len = payload[offset]
                if label_len == 0:
                    break
                if label_len > 63:
                    break  # Compression pointer or invalid
                offset += 1
                if offset + label_len > len(payload):
                    break
                labels.append(payload[offset: offset + label_len].decode("ascii", errors="replace"))
                offset += label_len
        except IndexError:
            pass

        return ".".join(labels) if labels else None


# =============================================================================
# QUIC SNI Extractor (simplified)
# =============================================================================

class QUICSNIExtractor:
    """
    Simplified QUIC Initial packet SNI extractor.

    QUIC Initial packets embed a TLS Client Hello inside CRYPTO frames.
    This extractor searches for the Client Hello pattern within the QUIC payload.
    """

    @staticmethod
    def is_quic_initial(payload: bytes) -> bool:
        if len(payload) < 5:
            return False
        # Long header: first bit set
        return bool(payload[0] & 0x80)

    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        if not QUICSNIExtractor.is_quic_initial(payload):
            return None

        # Brute-force search for a Client Hello handshake type byte
        for i in range(len(payload) - 50):
            if payload[i] == 0x01:  # Client Hello
                # Try to treat bytes before this as a TLS record header
                start = max(0, i - 5)
                result = SNIExtractor.extract(payload[start:])
                if result:
                    return result

        return None
