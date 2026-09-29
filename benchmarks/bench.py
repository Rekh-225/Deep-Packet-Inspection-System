#!/usr/bin/env python3
"""
Reproducible local benchmark for the DPI engines.

Two things are measured and reported SEPARATELY:

1. Throughput — wall-clock time to process a synthetic capture end to end
   (read, parse, classify, apply rules, write filtered pcap), for the simple
   engine and for several multi-threaded layouts.  Best-of-N and median.
2. Classification agreement — for every flow in the synthetic capture the
   expected heuristic class is known by construction; the script reports how
   many flows the engine labelled as expected.  This is agreement with the
   generator's ground truth on clean, single-segment synthetic traffic.  It is
   NOT a real-world accuracy figure and must not be quoted as one.

The capture is generated deterministically (fixed seed, fixed bytes), so the
same command on the same machine and Python gives comparable numbers.  Machine
and input details are printed with the results so claims stay tied to them.

Usage:
    python benchmarks/bench.py                       # default: ~51k packets, 3 repetitions
    python benchmarks/bench.py --sites 6000 --reps 5 --json benchmarks/last_run.json
    python benchmarks/bench.py --layouts 1x1 2x2     # restrict mt layouts
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import platform
import statistics
import sys
import tempfile
import time
from typing import Dict, List, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tests import fixtures as fx  # noqa: E402
from dpi import __version__  # noqa: E402
from dpi.engine import DPIEngine  # noqa: E402
from dpi.engine_mt import DPIEngineMT  # noqa: E402
from dpi.types import AppType  # noqa: E402

CLIENT = "192.0.2.10"

# (name, expected heuristic class) -- expected values follow the static pattern
# table in dpi/types.py by construction.
TLS_NAMES: List[Tuple[str, str]] = [
    ("www.youtube.com", "YouTube"), ("www.netflix.com", "Netflix"), ("github.com", "GitHub"),
    ("www.facebook.com", "Facebook"), ("api.twitter.com", "Twitter/X"), ("open.spotify.com", "Spotify"),
    ("www.example.org", "HTTPS"), ("cdn.unknown-service.test", "HTTPS"),
]
HTTP_NAMES: List[Tuple[str, str]] = [("example.com", "HTTPS"), ("www.microsoft.com", "Microsoft")]
DNS_NAMES: List[str] = ["www.google.com", "api.twitter.com", "cdn.unknown-service.test"]


def generate(sites: int, bulk_acks: int) -> Tuple[List[bytes], Dict[Tuple, str], Dict[str, int]]:
    """
    Build the capture.  Returns (packets, expected_by_flow_key, composition).

    Per site: one TLS flow (4 handshake pkts + Client Hello + ``bulk_acks`` ACKs),
    one HTTP flow (2 pkts), one DNS query.  Flow key is (src_ip, src_port, dst_ip, dst_port).
    """
    pkts: List[bytes] = []
    expected: Dict[Tuple, str] = {}
    comp = {"tls_flows": 0, "http_flows": 0, "dns_flows": 0, "reverse_flows": 0, "packets": 0}
    port = 20000
    for i in range(sites):
        server = f"198.51.100.{(i % 250) + 1}"
        sni, sni_app = TLS_NAMES[i % len(TLS_NAMES)]
        pkts += fx.tls_flow(CLIENT, server, port, sni)
        pkts += [fx.tcp_packet(CLIENT, server, port, 443, fx.TCP_ACK) for _ in range(bulk_acks)]
        expected[(CLIENT, port, server, 443)] = sni_app
        expected[(server, 443, CLIENT, port)] = "Unknown"      # SYN-ACK direction: no name, not port 443 dst
        comp["tls_flows"] += 1; comp["reverse_flows"] += 1
        port += 1

        host, host_app = HTTP_NAMES[i % len(HTTP_NAMES)]
        pkts += fx.http_flow(CLIENT, server, port, host)
        expected[(CLIENT, port, server, 80)] = host_app
        comp["http_flows"] += 1
        port += 1

        pkts.append(fx.dns_packet(CLIENT, port, DNS_NAMES[i % len(DNS_NAMES)], resolver="192.0.2.53"))
        expected[(CLIENT, port, "192.0.2.53", 53)] = "DNS"
        comp["dns_flows"] += 1
        port += 1
        if port > 60000:
            port = 20000
    comp["packets"] = len(pkts)
    return pkts, expected, comp


def machine_info() -> Dict[str, str]:
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or "unknown",
        "cpu_count": str(os.cpu_count()),
        "python": f"{platform.python_implementation()} {platform.python_version()}",
        "gil": str(getattr(sys, "_is_gil_enabled", lambda: True)()),
        "dpi_engine": __version__,
    }


def time_run(make_engine, in_path: str, out_path: str, reps: int) -> Tuple[List[float], object]:
    times = []
    eng = None
    for _ in range(reps):
        eng = make_engine()
        eng.block_app("YouTube")
        t0 = time.perf_counter()
        with contextlib.redirect_stdout(io.StringIO()):
            eng.process_file(in_path, out_path)
        times.append(time.perf_counter() - t0)
        if not eng.stats.reconciles():
            raise SystemExit("accounting did not reconcile: " + str(vars(eng.stats)))
    return times, eng


def agreement(engine, expected: Dict[Tuple, str]) -> Dict[str, object]:
    from dpi.types import ip_to_str
    by_method = {}
    total = agree = 0
    mismatches = []
    for c in engine.connections():
        key = (ip_to_str(c.tuple.src_ip), c.tuple.src_port, ip_to_str(c.tuple.dst_ip), c.tuple.dst_port)
        want = expected.get(key)
        if want is None:
            continue
        got = c.app_type.value
        total += 1
        m = by_method.setdefault(c.classified_by, {"flows": 0, "agree": 0})
        m["flows"] += 1
        if got == want:
            agree += 1
            m["agree"] += 1
        elif len(mismatches) < 10:
            mismatches.append({"flow": key, "expected": want, "got": got, "method": c.classified_by})
    return {
        "labelled_flows": total,
        "agree": agree,
        "agreement_rate": (agree / total) if total else None,
        "by_method": by_method,
        "sample_mismatches": mismatches,
        "caveat": (
            "Agreement with the generator's ground truth on synthetic, single-segment traffic whose "
            "names were chosen from the pattern table. Not a real-world accuracy measurement."
        ),
    }


def parse_layout(s: str) -> Tuple[int, int]:
    a, b = s.lower().split("x")
    return int(a), int(b)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sites", type=int, default=3000, help="synthetic sites (each = 3 flows); default 3000")
    ap.add_argument("--bulk-acks", type=int, default=10, help="extra ACKs per TLS flow; default 10")
    ap.add_argument("--reps", type=int, default=3, help="repetitions per configuration; default 3")
    ap.add_argument("--layouts", nargs="*", default=["1x1", "1x2", "2x2", "2x4"], help="mt layouts LBSxFPS")
    ap.add_argument("--json", metavar="FILE", help="also write results to FILE")
    ap.add_argument("--input", metavar="PCAP", help="benchmark this capture instead of generating one "
                                                     "(classification agreement is then skipped)")
    args = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix="dpi-bench-")
    out_path = os.path.join(tmp, "out.pcap")
    expected: Dict[Tuple, str] = {}
    if args.input:
        in_path = args.input
        comp = {"packets": None, "note": "user-supplied capture"}
    else:
        pkts, expected, comp = generate(args.sites, args.bulk_acks)
        in_path = os.path.join(tmp, "bench.pcap")
        fx.write_pcap(in_path, pkts)
    size = os.path.getsize(in_path)

    results = {
        "machine": machine_info(),
        "input": {"path": in_path, "bytes": size, "composition": comp, "generator": {
            "sites": args.sites, "bulk_acks": args.bulk_acks} if not args.input else None},
        "rules": ["--block-app YouTube"],
        "reps": args.reps,
        "throughput": [],
        "classification_agreement": None,
    }

    print("== Machine ==")
    for k, v in results["machine"].items():
        print(f"  {k:<11} {v}")
    print("== Input ==")
    print(f"  {in_path}  ({size/1e6:.2f} MB)")
    for k, v in comp.items():
        print(f"  {k:<14} {v}")
    print(f"== Throughput (rules: --block-app YouTube; {args.reps} reps; best / median) ==")

    configs = [("simple", DPIEngine)]
    for lay in args.layouts:
        lbs, fps = parse_layout(lay)
        configs.append((f"mt {lbs}x{fps}", lambda lbs=lbs, fps=fps: DPIEngineMT(lbs, fps)))

    ref_stats = None
    ref_out = None
    for label, make in configs:
        times, eng = time_run(make, in_path, out_path, args.reps)
        n = eng.stats.total_packets
        best, med = min(times), statistics.median(times)
        with open(out_path, "rb") as f:
            out_bytes = f.read()
        if ref_stats is None:
            ref_stats, ref_out = vars(eng.stats).copy(), out_bytes
            same = True
        else:
            same = vars(eng.stats) == ref_stats and out_bytes == ref_out
        row = {
            "config": label, "packets": n, "retained": eng.stats.forwarded_packets,
            "rule_filtered": eng.stats.dropped_packets,
            "best_s": round(best, 4), "median_s": round(med, 4),
            "best_pps": round(n / best), "best_MBps": round(size / best / 1e6, 2),
            "identical_to_simple": same,
        }
        results["throughput"].append(row)
        print(f"  {label:<10} {best:7.3f}s / {med:7.3f}s   {n/best:9.0f} pkt/s  {size/best/1e6:6.2f} MB/s"
              f"   filtered {eng.stats.dropped_packets}   output+stats identical to simple: {same}")
        if label == "simple" and expected:
            results["classification_agreement"] = agreement(eng, expected)

    agr = results["classification_agreement"]
    print("== Classification agreement (separate from throughput) ==")
    if agr:
        print(f"  labelled flows: {agr['labelled_flows']}   agree: {agr['agree']}   "
              f"rate: {agr['agreement_rate']:.4f}")
        for m, d in sorted(agr["by_method"].items()):
            print(f"    method {m:<14} {d['agree']}/{d['flows']}")
        if agr["sample_mismatches"]:
            print("  mismatches (first 10):")
            for mm in agr["sample_mismatches"]:
                print("   ", mm)
        print(f"  caveat: {agr['caveat']}")
    else:
        print("  skipped (no ground truth for a user-supplied capture)")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"results written to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
