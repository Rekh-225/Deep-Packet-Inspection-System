"""
DPI Engine - Deep Packet Inspection System
==========================================

A Python-based deep packet inspection engine that reads PCAP captures,
classifies traffic by application (YouTube, Facebook, etc.), and applies
blocking rules.

Usage:
    from dpi.engine import DPIEngine

    engine = DPIEngine()
    engine.block_app("YouTube")
    engine.process_file("input.pcap", "output.pcap")
"""

from dpi.types import AppType, ConnectionState, PacketAction, FiveTuple
from dpi.engine import DPIEngine
from dpi.rule_manager import RuleManager

__version__ = "2.0.0"
__all__ = [
    "DPIEngine",
    "RuleManager",
    "AppType",
    "ConnectionState",
    "PacketAction",
    "FiveTuple",
]
