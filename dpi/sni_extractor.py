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

        Every length field is honoured strictly: the handshake message must lie
        entirely inside the declared record, the Client Hello body inside the
        declared handshake length, the extensions block inside the body, each
        extension inside the block, and the SNI list / entry / name inside the
        extension.  Bytes after the declared record are never read, so a
        truncated or inconsistent message yields ``None`` rather than a name
        assembled from trailing data.

        Returns the hostname (ASCII, 1..255 bytes), or ``None``.
        """
        if not SNIExtractor.is_tls_client_hello(payload):
            return None

        try:
            record_len = struct.unpack_from("!H", payload, 3)[0]
            record = payload[5: 5 + record_len]
            if len(record) != record_len or record_len < 4:
                return None

            # Handshake header: type (1) + length (3); body must be complete in the record
            hs_len = int.from_bytes(record[1:4], "big")
            body = record[4: 4 + hs_len]
            if len(body) != hs_len:
                return None

            offset = 0
            # Client Hello body: version (2) + random (32)
            offset += 2 + 32
            if offset >= len(body):
                return None

            # Session ID
            session_id_len = body[offset]
            offset += 1 + session_id_len
            if offset + 2 > len(body):
                return None

            # Cipher suites
            cipher_suites_len = struct.unpack_from("!H", body, offset)[0]
            offset += 2 + cipher_suites_len
            if offset >= len(body):
                return None

            # Compression methods
            comp_len = body[offset]
            offset += 1 + comp_len
            if offset + 2 > len(body):
                return None

            # Extensions block must fit exactly inside the body
            extensions_len = struct.unpack_from("!H", body, offset)[0]
            offset += 2
            extensions_end = offset + extensions_len
            if extensions_end > len(body):
                return None

            # Walk extensions looking for SNI (type 0x0000)
            while offset + 4 <= extensions_end:
                ext_type = struct.unpack_from("!H", body, offset)[0]
                ext_len  = struct.unpack_from("!H", body, offset + 2)[0]
                offset += 4
                ext_end = offset + ext_len
                if ext_end > extensions_end:
                    return None   # extension overruns the block: structurally invalid

                if ext_type == _EXTENSION_SNI:
                    # SNI extension: list_length (2) + [type (1) + name_length (2) + name]...
                    if ext_len < 2:
                        return None
                    list_len = struct.unpack_from("!H", body, offset)[0]
                    list_end = offset + 2 + list_len
                    if list_end > ext_end:
                        return None
                    pos = offset + 2
                    while pos + 3 <= list_end:
                        entry_type = body[pos]
                        name_len = struct.unpack_from("!H", body, pos + 1)[0]
                        name_end = pos + 3 + name_len
                        if name_end > list_end:
                            return None
                        if entry_type == _SNI_TYPE_HOSTNAME:
                            if name_len == 0 or name_len > 255:
                                return None
                            try:
                                return body[pos + 3: name_end].decode("ascii")
                            except UnicodeDecodeError:
                                return None
                        pos = name_end
                    return None   # SNI extension present but no host_name entry

                offset = ext_end

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
                try:
                    host = payload[start:end].decode("ascii").strip()
                except UnicodeDecodeError:
                    return None
                # Remove port if present
                if ":" in host:
                    host = host.split(":")[0]
                # Bound like a DNS name; longer or empty values are not a host name.
                if not host or len(host) > 255:
                    return None
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
        """
        Extract the first question name from a DNS query payload.

        The question must be complete: every label fully present (length
        1..63), a terminating zero label, and the 4-byte QTYPE / QCLASS after
        it.  Compression pointers (label byte >= 0xC0) are not supported in the
        question section and are rejected explicitly; label bytes 0x40..0xBF
        are invalid.  Anything incomplete or inconsistent yields ``None`` --
        never a partial name.  Name is limited to 253 characters.
        """
        if not DNSExtractor.is_dns_query(payload):
            return None

        offset = 12  # Skip DNS header
        labels: list[str] = []
        total = 0

        try:
            while True:
                if offset >= len(payload):
                    return None                       # ran out before the terminator
                label_len = payload[offset]
                offset += 1
                if label_len == 0:
                    break
                if label_len >= 0xC0:
                    return None                       # compression pointer: unsupported here
                if label_len > 63:
                    return None                       # reserved / invalid label type
                if offset + label_len > len(payload):
                    return None                       # label cut short
                total += label_len + 1
                if total > 254:                       # wire form without terminator; 253 chars printed
                    return None
                try:
                    labels.append(payload[offset: offset + label_len].decode("ascii"))
                except UnicodeDecodeError:
                    return None
                offset += label_len
            if not labels:
                return None                           # root name: nothing to report
            if offset + 4 > len(payload):
                return None                           # QTYPE / QCLASS missing
        except IndexError:
            return None

        return ".".join(labels)


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
