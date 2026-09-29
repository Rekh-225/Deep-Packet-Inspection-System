#!/usr/bin/env python3
"""
Generate the sample captures in ``samples/captures/`` deterministically.

All traffic is synthetic: frames are assembled byte-by-byte with ``struct``
using the builders in ``tests/fixtures.py``.  Addresses come from the IANA
documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24); MACs are
locally administered.  No real capture data is included, so the files may be
redistributed freely.

Running this script from a checkout regenerates every file byte-for-byte
(``tests/test_samples.py`` verifies that).  Expected results per capture and
rule set are stated in ``samples/expected.json`` by construction and are
checked against both engines by the same test module.

Usage:
    python samples/make_samples.py [--check]
"""

from __future__ import annotations

import argparse
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tests import fixtures as fx  # noqa: E402

CAPTURES = os.path.join(ROOT, "samples", "captures")

CLIENT = "192.0.2.10"           # TEST-NET-1
BLOCKED_CLIENT = "192.0.2.66"
RESOLVER = "192.0.2.53"
SERVERS = "198.51.100."         # TEST-NET-2
HOSTILE_SERVER = "203.0.113.13"  # TEST-NET-3

TLS_SITES = (
    (SERVERS + "1", "www.google.com"),
    (SERVERS + "2", "www.youtube.com"),
    (SERVERS + "3", "www.facebook.com"),
    (SERVERS + "4", "twitter.com"),
    (SERVERS + "5", "www.netflix.com"),
    (SERVERS + "6", "github.com"),
    (SERVERS + "7", "www.tiktok.com"),
    (SERVERS + "8", "www.example.org"),   # unrecognised SNI -> HTTPS
)
HTTP_SITES = (
    (SERVERS + "20", "example.com"),
    (SERVERS + "21", "httpbin.org"),
)
DNS_NAMES = ("www.google.com", "www.youtube.com", "api.twitter.com")


def mixed_supported() -> list:
    """44 packets: 8 TLS flows x4, 2 HTTP flows x2, 3 DNS queries, 5 SYNs from BLOCKED_CLIENT."""
    pkts, port = [], 50000
    for ip, sni in TLS_SITES:
        pkts += fx.tls_flow(CLIENT, ip, port, sni); port += 1
    for ip, host in HTTP_SITES:
        pkts += fx.http_flow(CLIENT, ip, port, host); port += 1
    for name in DNS_NAMES:
        pkts.append(fx.dns_packet(CLIENT, port, name, resolver=RESOLVER)); port += 1
    for _ in range(5):
        pkts.append(fx.tcp_packet(BLOCKED_CLIENT, SERVERS + "99", port, 443, fx.TCP_SYN)); port += 1
    assert len(pkts) == 44
    return pkts


def mixed_unsupported() -> list:
    """mixed_supported plus ARP, IPv6, ICMP (unsupported) and one truncated IPv4 header (malformed): 48."""
    pkts = mixed_supported()
    pkts.insert(0, fx.arp_packet())
    pkts.insert(10, fx.ipv6_packet())
    pkts.insert(20, fx.icmp_packet(CLIENT, SERVERS + "1"))
    pkts.append(fx.truncated_packet())
    assert len(pkts) == 48
    return pkts


HOSTILE_SNI = "<script>alert(1)</script>.evil.test"
HOSTILE_HOST = 'evil.test"><script>alert(2)</script>'
HOSTILE_DNS = "<img src=x>.evil.test"
MAX_SNI = "a" * 245 + ".long.test"          # 255 chars: the RFC 6066 maximum, accepted
OVERLONG_SNI = "b" * 290 + ".long.test"     # 300 chars: rejected by the extractor, flow stays HTTPS by port


def hostile_names() -> list:
    """15 packets: names with HTML/JS metacharacters, a maximum-length SNI, and an over-long SNI."""
    pkts = []
    pkts += fx.tls_flow(CLIENT, HOSTILE_SERVER, 51000, HOSTILE_SNI)      # 4
    pkts += fx.http_flow(CLIENT, HOSTILE_SERVER, 51001, HOSTILE_HOST)    # 2
    pkts.append(fx.dns_packet(CLIENT, 51002, HOSTILE_DNS, resolver=RESOLVER))  # 1
    pkts += fx.tls_flow(CLIENT, HOSTILE_SERVER, 51003, MAX_SNI)          # 4
    pkts += fx.tls_flow(CLIENT, HOSTILE_SERVER, 51004, OVERLONG_SNI)     # 4
    assert len(pkts) == 15
    return pkts


def write_bytes(name: str, data: bytes) -> None:
    with open(os.path.join(CAPTURES, name), "wb") as f:
        f.write(data)


def pcap_bytes(packets) -> bytes:
    tmp = os.path.join(CAPTURES, ".tmp.pcap")
    fx.write_pcap(tmp, packets)
    with open(tmp, "rb") as f:
        data = f.read()
    os.unlink(tmp)
    return data


def build_all() -> dict:
    files = {}
    good = pcap_bytes(mixed_supported())
    files["mixed_supported.pcap"] = good
    files["mixed_unsupported.pcap"] = pcap_bytes(mixed_unsupported())
    files["hostile_names.pcap"] = pcap_bytes(hostile_names())

    # Malformed lengths (must be rejected, exit status 1):
    files["truncated_body.pcap"] = good[:-10]                 # last packet body cut short
    files["truncated_header.pcap"] = good + b"\x00" * 7       # 7 stray bytes after last packet
    bad_len = bytearray(good)
    struct.pack_into("<I", bad_len, 24 + 8, 70000)            # incl_len of packet #0 > 65535
    files["oversized_record.pcap"] = bytes(bad_len)

    # Unsupported formats (must be rejected, exit status 1):
    files["nanosecond_magic.pcap"] = struct.pack("<I", 0xA1B23C4D) + good[4:]
    files["pcapng_stub.pcapng"] = struct.pack("<IIII", 0x0A0D0D0A, 28, 0x1A2B3C4D, 0x00010000) + b"\xff" * 8 + struct.pack("<I", 28)
    raw_ip = bytearray(good)
    struct.pack_into("<I", raw_ip, 20, 101)                    # LINKTYPE_RAW
    files["linktype_raw.pcap"] = bytes(raw_ip)
    files["empty.pcap"] = good[:24]                            # valid header, zero packets (accepted)
    files["short_header.pcap"] = good[:10]                     # not a pcap
    return files


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="verify existing files match instead of writing")
    args = ap.parse_args()

    os.makedirs(CAPTURES, exist_ok=True)
    files = build_all()
    mismatched = []
    for name, data in files.items():
        path = os.path.join(CAPTURES, name)
        if args.check:
            with open(path, "rb") as f:
                if f.read() != data:
                    mismatched.append(name)
        else:
            write_bytes(name, data)
            print(f"wrote {path} ({len(data)} bytes)")
    if mismatched:
        print("MISMATCH: " + ", ".join(mismatched))
        return 1
    if args.check:
        print(f"{len(files)} sample files match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
