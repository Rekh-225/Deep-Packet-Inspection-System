"""
Integration tests for the DPI Engine.

Tests the full pipeline: PCAP read → parse → classify → block → write.
"""

import os
import tempfile
import unittest

from dpi.engine import DPIEngine
from dpi.pcap_io import PcapReader


PCAP_PATH = os.path.join(os.path.dirname(__file__), "..", "test_dpi.pcap")


class TestDPIEngineSimple(unittest.TestCase):
    """Integration tests for the single-threaded DPI engine."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        self.tmp.close()

    def tearDown(self):
        if os.path.exists(self.tmp.name):
            os.unlink(self.tmp.name)

    def test_process_without_blocking(self):
        """Without blocking rules, all packets should be forwarded."""
        engine = DPIEngine()
        engine.process_file(PCAP_PATH, self.tmp.name)

        self.assertGreater(engine.stats.total_packets, 0)
        self.assertEqual(engine.stats.dropped_packets, 0)
        self.assertEqual(engine.stats.forwarded_packets, engine.stats.total_packets)

        # Output should be valid PCAP
        reader = PcapReader()
        self.assertTrue(reader.open(self.tmp.name))
        output_count = sum(1 for _ in reader)
        reader.close()
        self.assertEqual(output_count, engine.stats.total_packets)

    def test_process_with_app_blocking(self):
        """Blocking YouTube should reduce forwarded packet count."""
        engine = DPIEngine()
        engine.block_app("YouTube")
        engine.process_file(PCAP_PATH, self.tmp.name)

        self.assertGreater(engine.stats.dropped_packets, 0)
        self.assertEqual(
            engine.stats.forwarded_packets + engine.stats.dropped_packets,
            engine.stats.total_packets,
        )

    def test_process_with_ip_blocking(self):
        """Blocking IP 192.168.1.50 should drop those 5 test packets."""
        engine = DPIEngine()
        engine.block_ip("192.168.1.50")
        engine.process_file(PCAP_PATH, self.tmp.name)

        self.assertEqual(engine.stats.dropped_packets, 5)

    def test_output_smaller_when_blocking(self):
        """Output file should be smaller than input when blocking."""
        engine = DPIEngine()
        engine.block_ip("192.168.1.50")
        engine.block_app("YouTube")
        engine.process_file(PCAP_PATH, self.tmp.name)

        input_size = os.path.getsize(PCAP_PATH)
        output_size = os.path.getsize(self.tmp.name)
        self.assertLess(output_size, input_size)

    def test_detects_multiple_apps(self):
        """Engine should detect various applications from the test PCAP."""
        engine = DPIEngine()
        engine.process_file(PCAP_PATH, self.tmp.name)

        detected_apps = set(engine._app_stats.keys())
        # Test PCAP contains at least these apps
        from dpi.types import AppType
        for expected in (AppType.DNS, AppType.HTTPS):
            self.assertIn(expected, detected_apps)


class TestDPIEngineMT(unittest.TestCase):
    """Integration tests for the multi-threaded DPI engine."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        self.tmp.close()

    def tearDown(self):
        if os.path.exists(self.tmp.name):
            os.unlink(self.tmp.name)

    def test_mt_process_without_blocking(self):
        from dpi.engine_mt import DPIEngineMT

        engine = DPIEngineMT(num_lbs=2, fps_per_lb=2)
        engine.process_file(PCAP_PATH, self.tmp.name)

        self.assertGreater(engine.stats.total_packets, 0)
        self.assertEqual(engine.stats.dropped_packets, 0)
        self.assertEqual(engine.stats.forwarded_packets, engine.stats.total_packets)

    def test_mt_blocking_matches_simple(self):
        """MT mode should drop the same number of packets as simple mode."""
        from dpi.engine_mt import DPIEngineMT

        # Simple mode
        tmp1 = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        tmp1.close()
        engine1 = DPIEngine()
        engine1.block_ip("192.168.1.50")
        engine1.process_file(PCAP_PATH, tmp1.name)

        # MT mode
        engine2 = DPIEngineMT(num_lbs=2, fps_per_lb=2)
        engine2.block_ip("192.168.1.50")
        engine2.process_file(PCAP_PATH, self.tmp.name)

        self.assertEqual(engine1.stats.dropped_packets, engine2.stats.dropped_packets)
        self.assertEqual(engine1.stats.total_packets, engine2.stats.total_packets)

        os.unlink(tmp1.name)


if __name__ == "__main__":
    unittest.main()
