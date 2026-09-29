#!/usr/bin/env python3
"""
Short demo: run dpi-engine on the synthetic sample captures and write filtered
captures plus JSON/HTML reports to ./demo_out (local only).

    python demo.py                    # writes demo_out/
    python demo.py --samples-reports  # also refresh samples/reports/ (reproducible: no timestamps,
                                      # repo-relative paths, filtered pcaps not kept)
"""

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from dpi.cli import main as dpi_main  # noqa: E402

RUNS = [
    ("mixed_supported.block_streaming", "mixed_supported.pcap", "simple",
     ["--rules-file", "samples/rules/block_streaming.rules"]),
    ("mixed_unsupported.block_client_and_dns", "mixed_unsupported.pcap", "mt",
     ["--rules-file", "samples/rules/block_client_and_dns.rules"]),
    ("hostile_names.block_evil_domain", "hostile_names.pcap", "mt",
     ["--rules-file", "samples/rules/block_evil_domain.rules"]),
]


def run(report_dir: str, pcap_dir: str) -> int:
    """Run every demo case; paths are passed relative to the repo root so reports are portable."""
    os.makedirs(report_dir, exist_ok=True)
    os.makedirs(pcap_dir, exist_ok=True)
    os.chdir(ROOT)
    rel = lambda p: os.path.relpath(p, ROOT).replace(os.sep, "/")
    worst = 0
    for name, capture, mode, extra in RUNS:
        args = [
            f"samples/captures/{capture}", rel(os.path.join(pcap_dir, name + ".filtered.pcap")),
            "--mode", mode, "--report-no-timestamp",
            "--report-json", rel(os.path.join(report_dir, name + ".report.json")),
            "--report-html", rel(os.path.join(report_dir, name + ".report.html")),
            *extra,
        ]
        print(f"\n### {name} ({mode})")
        rc = dpi_main(args)
        print(f"### exit status {rc}")
        worst = max(worst, rc)

    print("\n### rejected input example (expected exit status 1):")
    never = os.path.join(pcap_dir, "never-written.pcap")
    rc = dpi_main(["samples/captures/truncated_body.pcap", rel(never)])
    print(f"### exit status {rc}")
    if rc != 1 or os.path.exists(never):
        worst = max(worst, 1)
    return worst


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=os.path.join(ROOT, "demo_out"))
    ap.add_argument("--samples-reports", action="store_true",
                    help="also write reproducible reports into samples/reports/")
    a = ap.parse_args()
    status = run(a.out, a.out)
    if a.samples_reports:
        # Filtered pcaps still go to demo_out; only the reports land in samples/reports.
        status = max(status, run(os.path.join(ROOT, "samples", "reports"), a.out))
    print(f"\nDone. Outputs in {a.out}")
    sys.exit(status)
