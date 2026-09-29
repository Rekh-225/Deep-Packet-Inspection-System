"""
Deterministic packet / PCAP fixture builders for engine tests.

Everything here is hand-assembled with ``struct`` from the wire formats
(Ethernet, IPv4, TCP, UDP, TLS Client Hello, HTTP, DNS).  It deliberately
does not import anything from ``dpi`` so that fixture expectations are
independent of the implementation under test.

Provenance note: ``test_dpi.pcap`` in the repository root was produced by
``generate_test_pcap.py`` (a separate hand-written packet crafter, not the
DPI parser).  The builders below are an independent re-implementation and
use fixed values (no ``random``), so byte-for-byte expectations can be
stated in tests.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Tuple

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_PSH = 0x08
TCP_ACK = 0x10

CLIENT_MAC = "00:11:22:33:44:55"
GATEWAY_MAC = "aa:bb:cc:dd:ee:ff"


# -----------------------------------------------------------------------------
# Layer builders
# -----------------------------------------------------------------------------

def eth(src_mac: str = CLIENT_MAC, dst_mac: str = GATEWAY_MAC, ether_type: int = ETHERTYPE_IPV4) -> bytes:
    return (
        bytes.fromhex(dst_mac.replace(":", ""))
        + bytes.fromhex(src_mac.replace(":", ""))
        + struct.pack("!H", ether_type)
    )


def ipv4(src_ip: str, dst_ip: str, protocol: int, payload_len: int, ident: int = 1,
         total_len: Optional[int] = None, flags_frag: int = 0x4000, version_ihl: int = 0x45) -> bytes:
    """IPv4 header. ``total_len`` / ``flags_frag`` / ``version_ihl`` may be overridden to craft bad packets."""
    header = struct.pack(
        "!BBHHHBBH",
        version_ihl, 0, 20 + payload_len if total_len is None else total_len,
        ident & 0xFFFF, flags_frag, 64, protocol, 0,
    )
    header += bytes(int(x) for x in src_ip.split("."))
    header += bytes(int(x) for x in dst_ip.split("."))
    return header


IP_FLAG_DF = 0x4000
IP_FLAG_MF = 0x2000


def tcp(src_port: int, dst_port: int, flags: int, seq: int = 1, ack: int = 0, data_offset: int = 5) -> bytes:
    return struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, data_offset << 4, flags, 65535, 0, 0)


def udp(src_port: int, dst_port: int, payload_len: int, length: Optional[int] = None) -> bytes:
    return struct.pack("!HHHH", src_port, dst_port, 8 + payload_len if length is None else length, 0)


def tls_client_hello(sni: str) -> bytes:
    sni_bytes = sni.encode("ascii")
    sni_entry = struct.pack("!BH", 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
    supported_versions = struct.pack("!HHB", 0x002B, 3, 2) + struct.pack("!H", 0x0304)
    extensions = sni_ext + supported_versions
    body = (
        struct.pack("!H", 0x0303)
        + bytes(range(32))
        + struct.pack("B", 0)
        + struct.pack("!H", 4) + struct.pack("!HH", 0x1301, 0x1302)
        + struct.pack("BB", 1, 0)
        + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16" + struct.pack("!H", 0x0301) + struct.pack("!H", len(handshake)) + handshake


def http_get(host: str, path: str = "/") -> bytes:
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: fixture/1.0\r\nAccept: */*\r\n\r\n".encode()


def dns_query(domain: str, txid: int = 0x1234) -> bytes:
    question = b"".join(struct.pack("B", len(l)) + l.encode() for l in domain.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + question + struct.pack("!HH", 1, 1)


# -----------------------------------------------------------------------------
# Packet-level builders
# -----------------------------------------------------------------------------

def tcp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, flags: int,
               payload: bytes = b"", client_to_server: bool = True) -> bytes:
    smac, dmac = (CLIENT_MAC, GATEWAY_MAC) if client_to_server else (GATEWAY_MAC, CLIENT_MAC)
    seg = tcp(src_port, dst_port, flags) + payload
    return eth(smac, dmac) + ipv4(src_ip, dst_ip, PROTO_TCP, len(seg)) + seg


def udp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    dgram = udp(src_port, dst_port, len(payload)) + payload
    return eth() + ipv4(src_ip, dst_ip, PROTO_UDP, len(dgram)) + dgram


def arp_packet() -> bytes:
    return eth(ether_type=ETHERTYPE_ARP) + bytes(28)


def ipv6_packet() -> bytes:
    return eth(ether_type=ETHERTYPE_IPV6) + bytes(40)


def icmp_packet(src_ip: str = "10.0.0.1", dst_ip: str = "10.0.0.2") -> bytes:
    body = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"ping"
    return eth() + ipv4(src_ip, dst_ip, PROTO_ICMP, len(body)) + body


def truncated_packet() -> bytes:
    """Ethernet + IPv4 header claiming TCP, but cut before the TCP header."""
    return eth() + ipv4("10.0.0.1", "10.0.0.2", PROTO_TCP, 20)[:12]


def tls_flow(client_ip: str, server_ip: str, client_port: int, sni: str) -> List[bytes]:
    """Client SYN, server SYN-ACK, client ACK, client TLS Client Hello (4 packets)."""
    return [
        tcp_packet(client_ip, server_ip, client_port, 443, TCP_SYN),
        tcp_packet(server_ip, client_ip, 443, client_port, TCP_SYN | TCP_ACK, client_to_server=False),
        tcp_packet(client_ip, server_ip, client_port, 443, TCP_ACK),
        tcp_packet(client_ip, server_ip, client_port, 443, TCP_PSH | TCP_ACK, tls_client_hello(sni)),
    ]


def http_flow(client_ip: str, server_ip: str, client_port: int, host: str) -> List[bytes]:
    """Client SYN then HTTP GET (2 packets)."""
    return [
        tcp_packet(client_ip, server_ip, client_port, 80, TCP_SYN),
        tcp_packet(client_ip, server_ip, client_port, 80, TCP_PSH | TCP_ACK, http_get(host)),
    ]


def dns_packet(client_ip: str, client_port: int, domain: str, resolver: str = "8.8.8.8") -> bytes:
    return udp_packet(client_ip, resolver, client_port, 53, dns_query(domain))


# -----------------------------------------------------------------------------
# PCAP writer (independent of dpi.pcap_io)
# -----------------------------------------------------------------------------

def write_pcap(path: str, packets: Sequence[bytes], ts_start: int = 1_700_000_000) -> None:
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, data in enumerate(packets):
            f.write(struct.pack("<IIII", ts_start + i, i % 1_000_000, len(data), len(data)))
            f.write(data)


def write_pcap_records(path: str, records: Sequence[Tuple[int, int, bytes, int]]) -> None:
    """Write explicit (ts_sec, ts_usec, data, orig_len) records; orig_len may exceed len(data)."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts_sec, ts_usec, data, orig_len in records:
            f.write(struct.pack("<IIII", ts_sec, ts_usec, len(data), orig_len))
            f.write(data)


def read_pcap_records(path: str) -> List[Tuple[int, int, bytes, int]]:
    """Return (ts_sec, ts_usec, data, orig_len) records in file order (independent reader)."""
    out: List[Tuple[int, int, bytes, int]] = []
    with open(path, "rb") as f:
        hdr = f.read(24)
        assert len(hdr) == 24, "short global header"
        magic = struct.unpack("<I", hdr[:4])[0]
        assert magic == 0xA1B2C3D4, hex(magic)
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", ph)
            data = f.read(incl_len)
            assert len(data) == incl_len, "truncated packet body"
            out.append((ts_sec, ts_usec, data, orig_len))
    return out


def read_pcap(path: str) -> List[bytes]:
    """Return the raw packet bytes in file order (independent reader)."""
    return [r[2] for r in read_pcap_records(path)]


# -----------------------------------------------------------------------------
# Canned fixtures with independently stated expectations
# -----------------------------------------------------------------------------

@dataclass
class Fixture:
    packets: List[bytes]
    # Expectations stated by construction, not derived from the engine.
    supported: int
    unsupported: int
    malformed: int
    notes: str = ""

    @property
    def total(self) -> int:
        return len(self.packets)


CLIENT = "192.168.1.100"
BLOCKED_CLIENT = "192.168.1.50"

TLS_SITES: Sequence[Tuple[str, str]] = (
    ("142.250.185.206", "www.google.com"),
    ("142.250.185.110", "www.youtube.com"),
    ("157.240.1.35", "www.facebook.com"),
    ("104.244.42.65", "twitter.com"),
    ("23.52.167.61", "www.netflix.com"),
    ("140.82.114.4", "github.com"),
    ("99.86.0.100", "www.tiktok.com"),
    ("93.184.216.34", "www.example.org"),   # unrecognised SNI -> HTTPS
)
HTTP_SITES: Sequence[Tuple[str, str]] = (
    ("93.184.216.34", "example.com"),
    ("185.199.108.153", "httpbin.org"),
)
DNS_NAMES: Sequence[str] = ("www.google.com", "www.youtube.com", "api.twitter.com")


def mixed_supported_fixture() -> Fixture:
    """
    Fully supported traffic (IPv4 TCP/UDP only):

    * 8 TLS flows x 4 packets            = 32
    * 2 HTTP flows x 2 packets           =  4
    * 3 DNS queries                      =  3
    * 5 bare SYNs from BLOCKED_CLIENT    =  5
                                   total = 44
    """
    pkts: List[bytes] = []
    port = 50000
    for ip, sni in TLS_SITES:
        pkts += tls_flow(CLIENT, ip, port, sni)
        port += 1
    for ip, host in HTTP_SITES:
        pkts += http_flow(CLIENT, ip, port, host)
        port += 1
    for name in DNS_NAMES:
        pkts.append(dns_packet(CLIENT, port, name))
        port += 1
    for _ in range(5):
        pkts.append(tcp_packet(BLOCKED_CLIENT, "172.217.0.100", port, 443, TCP_SYN))
        port += 1
    assert len(pkts) == 44
    return Fixture(pkts, supported=44, unsupported=0, malformed=0,
                   notes="8 TLS, 2 HTTP, 3 DNS, 5 SYNs from blocked client")


def mixed_with_unsupported_fixture() -> Fixture:
    """mixed_supported_fixture() interleaved with 1 ARP, 1 IPv6, 1 ICMP and 1 truncated packet."""
    base = mixed_supported_fixture().packets
    pkts = list(base)
    pkts.insert(0, arp_packet())          # unsupported (non-IPv4 ethertype)
    pkts.insert(10, ipv6_packet())        # unsupported (non-IPv4 ethertype)
    pkts.insert(20, icmp_packet())        # unsupported (IPv4 but not TCP/UDP)
    pkts.append(truncated_packet())       # malformed (cut inside IP header)
    return Fixture(pkts, supported=44, unsupported=3, malformed=1,
                   notes="44 supported + ARP, IPv6, ICMP, truncated")


def many_flows_fixture(num_flows: int = 64, packets_per_flow: int = 3) -> Fixture:
    """num_flows distinct client ports to 10.1.0.1:443, packets_per_flow SYN/ACK/ACK each, interleaved."""
    pkts: List[bytes] = []
    for i in range(packets_per_flow):
        for f in range(num_flows):
            flags = TCP_SYN if i == 0 else TCP_ACK
            pkts.append(tcp_packet(CLIENT, "10.1.0.1", 40000 + f, 443, flags))
    return Fixture(pkts, supported=len(pkts), unsupported=0, malformed=0,
                   notes=f"{num_flows} flows x {packets_per_flow} packets, round-robin interleaved")


def uneven_flows_fixture(hot_packets: int = 300, cold_flows: int = 5) -> Fixture:
    """One hot flow with many packets plus a handful of single-packet flows, hot flow first."""
    pkts: List[bytes] = [tcp_packet(CLIENT, "10.2.0.1", 41000, 443, TCP_ACK) for _ in range(hot_packets)]
    for f in range(cold_flows):
        pkts.append(tcp_packet(CLIENT, "10.2.0.2", 42000 + f, 443, TCP_SYN))
    return Fixture(pkts, supported=len(pkts), unsupported=0, malformed=0,
                   notes=f"1 hot flow x {hot_packets} + {cold_flows} single-packet flows")
