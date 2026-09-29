"""
DPI Engine — Command-Line Interface
====================================

Process PCAP files with deep packet inspection, classify traffic by
application, and apply blocking rules.

Invocation (all equivalent after ``pip install .``):
    dpi-engine <input.pcap> <output.pcap> [options]
    python -m dpi <input.pcap> <output.pcap> [options]
    python cli.py <input.pcap> <output.pcap> [options]      # repo checkout

Examples:
    dpi-engine test_dpi.pcap output.pcap
    dpi-engine test_dpi.pcap output.pcap --block-app YouTube
    dpi-engine test_dpi.pcap output.pcap --block-app YouTube --block-ip 192.168.1.50
    dpi-engine test_dpi.pcap output.pcap --mode mt --lbs 4 --fps 4
    dpi-engine test_dpi.pcap output.pcap --report-json run.json --report-html run.html

Exit status:
    0    complete output written (and every requested report)
    1    processing failed (unreadable / unsupported / truncated input, unwritable
         output, worker error, flow limit, accounting mismatch); no output file
         is left at the destination
    2    usage error / rules file could not be loaded
    3    capture completed; report failed -- the output PCAP is complete and in
         place, but at least one requested report could not be written.  stderr
         lists which outputs exist and which failed.
    130  cancelled (Ctrl-C) before the output was committed; no output left
"""

from __future__ import annotations

import argparse
import datetime as _dt
import sys
from typing import List, Optional

from dpi import __version__
from dpi.inspection import DetectionLog
from dpi.types import FlowCapacity

EXIT_OK = 0
EXIT_PROCESSING_FAILED = 1
EXIT_USAGE = 2
EXIT_REPORT_FAILED = 3          # capture completed; report failed
EXIT_CANCELLED = 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dpi-engine",
        description="DPI Engine — Deep Packet Inspection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  %(prog)s capture.pcap filtered.pcap --block-app YouTube
  %(prog)s capture.pcap filtered.pcap --block-ip 192.168.1.50 --block-domain tiktok
  %(prog)s capture.pcap filtered.pcap --mode mt --lbs 4 --fps 2
  %(prog)s capture.pcap filtered.pcap --report-json run.json --report-html run.html

Input must be a classic .pcap (microsecond timestamps, either byte order) with
Ethernet link type. pcapng, nanosecond pcap and other link types are rejected.
""",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    parser.add_argument("input", help="Input PCAP file path")
    parser.add_argument("output", help="Output PCAP file path (filtered)")

    # Blocking rules
    rules_group = parser.add_argument_group("blocking rules")
    rules_group.add_argument(
        "--block-ip", action="append", default=[], metavar="IP",
        help="Block traffic from source IP (can be repeated)",
    )
    rules_group.add_argument(
        "--block-app", action="append", default=[], metavar="APP",
        help="Block application: YouTube, Facebook, TikTok, etc. (can be repeated)",
    )
    rules_group.add_argument(
        "--block-domain", action="append", default=[], metavar="DOMAIN",
        help="Block domain by substring match, or *.suffix wildcard (can be repeated)",
    )
    rules_group.add_argument(
        "--block-port", action="append", default=[], type=int, metavar="PORT",
        help="Block destination port (can be repeated)",
    )
    rules_group.add_argument(
        "--rules-file", metavar="FILE",
        help="Load blocking rules from a file",
    )

    # Engine mode
    mode_group = parser.add_argument_group("engine mode")
    mode_group.add_argument(
        "--mode", choices=["simple", "mt"], default="simple",
        help="Engine mode: 'simple' (single-threaded) or 'mt' (multi-threaded). Default: simple",
    )
    mode_group.add_argument(
        "--lbs", type=int, default=2, metavar="N",
        help="Number of load balancer threads (mt mode only, default: 2)",
    )
    mode_group.add_argument(
        "--fps", type=int, default=2, metavar="N",
        help="Number of fast-path threads per LB (mt mode only, default: 2)",
    )
    mode_group.add_argument(
        "--queue-size", type=int, default=10_000, metavar="N",
        help="Max packets in flight between reader and writer (mt mode only, default: 10000)",
    )
    mode_group.add_argument(
        "--max-flows", type=int, default=FlowCapacity.DEFAULT_MAX_FLOWS, metavar="N",
        help="Global limit on tracked flows for the run, identical in both modes "
             f"(default: {FlowCapacity.DEFAULT_MAX_FLOWS}); exceeding it fails the run",
    )

    # Reports
    report_group = parser.add_argument_group("reports (written only after a successful run)")
    report_group.add_argument("--report-json", metavar="FILE", help="Write a JSON report to FILE")
    report_group.add_argument("--report-html", metavar="FILE", help="Write a static HTML report to FILE")
    report_group.add_argument(
        "--report-max-flows", type=int, default=1000, metavar="N",
        help="List at most N flows in reports (default: 1000; the report records the true total)",
    )
    report_group.add_argument(
        "--report-no-timestamp", action="store_true",
        help="Omit the generation timestamp from reports (for reproducible output)",
    )
    report_group.add_argument(
        "--max-report-detail", type=int, default=DetectionLog.DEFAULT_LIMIT, metavar="N",
        help="Keep at most N detected names and N blocked-flow entries for the console/report "
             f"detail (default: {DetectionLog.DEFAULT_LIMIT}); aggregate counts stay exact",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    # Ensure UTF-8 output on Windows consoles
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.lbs < 1 or args.fps < 1 or args.queue_size < 1 or args.max_flows < 1:
        parser.error("--lbs, --fps, --queue-size and --max-flows must be >= 1")
    if args.report_max_flows < 0 or args.max_report_detail < 0:
        parser.error("--report-max-flows and --max-report-detail must be >= 0")

    try:
        return _run(args)
    except KeyboardInterrupt:
        # Interrupt outside the engine (e.g. during rule loading or report writing).
        print("Cancelled: interrupted", file=sys.stderr)
        return EXIT_CANCELLED


def _run(args: argparse.Namespace) -> int:
    from dpi.types import ProcessingCancelled, ProcessingError

    # Create engine
    if args.mode == "mt":
        from dpi.engine_mt import DPIEngineMT
        engine = DPIEngineMT(num_lbs=args.lbs, fps_per_lb=args.fps, queue_size=args.queue_size,
                             max_flows=args.max_flows, max_report_detail=args.max_report_detail)
    else:
        from dpi.engine import DPIEngine
        engine = DPIEngine(max_flows=args.max_flows, max_report_detail=args.max_report_detail)

    # Apply rules
    if args.rules_file and not engine.load_rules(args.rules_file):
        print(f"Error: could not load rules file: {args.rules_file}", file=sys.stderr)
        return EXIT_USAGE

    for ip in args.block_ip:
        engine.block_ip(ip)
    for app in args.block_app:
        engine.block_app(app)
    for domain in args.block_domain:
        engine.block_domain(domain)
    for port in args.block_port:
        engine.block_port(port)

    # Process. Any failure to produce a complete output is a nonzero exit.
    try:
        engine.process_file(args.input, args.output)
    except ProcessingCancelled as e:
        print(f"Cancelled: {e}", file=sys.stderr)
        return EXIT_CANCELLED
    except ProcessingError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_PROCESSING_FAILED

    # Reports (only after a complete, committed capture).  A report failure does
    # not undo the capture: exit 3 = "capture completed; report failed".
    if not (args.report_json or args.report_html):
        return EXIT_OK

    from dpi import report as _report
    generated_at = None if args.report_no_timestamp else (
        _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()
    )
    outcomes = {}   # label -> (path, error or None)
    try:
        rep = _report.build_report(
            engine, args.input, args.output,
            max_flows=args.report_max_flows, generated_at=generated_at,
        )
    except Exception as e:  # noqa: BLE001 -- report building must never look like a capture failure
        for label, path in (("JSON report", args.report_json), ("HTML report", args.report_html)):
            if path:
                outcomes[label] = (path, f"{type(e).__name__}: {e}")
    else:
        for label, path, writer in (("JSON report", args.report_json, _report.write_json),
                                    ("HTML report", args.report_html, _report.write_html)):
            if not path:
                continue
            try:
                writer(rep, path)
                outcomes[label] = (path, None)
                print(f"{label} written to: {path}")
            except OSError as e:
                outcomes[label] = (path, str(e))

    failed = {k: v for k, v in outcomes.items() if v[1] is not None}
    if not failed:
        return EXIT_OK

    print("capture completed; report failed", file=sys.stderr)
    print(f"  capture:      written  {args.output}", file=sys.stderr)
    for label, (path, err) in outcomes.items():
        status = "written" if err is None else "FAILED "
        print(f"  {label + ':':<13} {status}  {path}" + (f"  ({err})" if err else ""), file=sys.stderr)
    return EXIT_REPORT_FAILED


if __name__ == "__main__":
    sys.exit(main())
