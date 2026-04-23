#!/usr/bin/env python3
"""
DPI Engine — Command-Line Interface
====================================

Process PCAP files with deep packet inspection, classify traffic by
application, and apply blocking rules.

Usage:
    python cli.py <input.pcap> <output.pcap> [options]

Examples:
    python cli.py test_dpi.pcap output.pcap
    python cli.py test_dpi.pcap output.pcap --block-app YouTube
    python cli.py test_dpi.pcap output.pcap --block-app YouTube --block-ip 192.168.1.50
    python cli.py test_dpi.pcap output.pcap --mode mt --lbs 4 --fps 4
"""

from __future__ import annotations

import argparse
import sys


def main() -> int:
    # Ensure UTF-8 output on Windows consoles
    import io
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="DPI Engine — Deep Packet Inspection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  %(prog)s capture.pcap filtered.pcap --block-app YouTube
  %(prog)s capture.pcap filtered.pcap --block-ip 192.168.1.50 --block-domain tiktok
  %(prog)s capture.pcap filtered.pcap --mode mt --lbs 4 --fps 2
""",
    )

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
        help="Block domain by substring match (can be repeated)",
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

    args = parser.parse_args()

    # Create engine
    if args.mode == "mt":
        from dpi.engine_mt import DPIEngineMT
        engine = DPIEngineMT(num_lbs=args.lbs, fps_per_lb=args.fps)
    else:
        from dpi.engine import DPIEngine
        engine = DPIEngine()

    # Apply rules
    if args.rules_file:
        engine.load_rules(args.rules_file)

    for ip in args.block_ip:
        engine.block_ip(ip)
    for app in args.block_app:
        engine.block_app(app)
    for domain in args.block_domain:
        engine.block_domain(domain)
    for port in args.block_port:
        engine.rule_manager.block_port(port)

    # Process
    engine.process_file(args.input, args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
