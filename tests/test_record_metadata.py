"""
Review finding 5: retained packets must keep their PCAP record metadata
(timestamp, captured bytes, captured length, original wire length), in both
engines and after out-of-order worker completion.
"""

import contextlib
import io
import os
import tempfile
import threading
import unittest

from dpi.engine import DPIEngine
from dpi.engine_mt import DPIEngineMT, route
from dpi.inspection import make_tuple
from dpi.packet_parser import PacketParser

from tests import fixtures as fx

WAIT = 20.0


def _run(engine, in_path, out_path):
    with contextlib.redirect_stdout(io.StringIO()):
        engine.process_file(in_path, out_path)


class TestRecordMetadata(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.in_path = os.path.join(self.dir.name, "in.pcap")

    def tearDown(self):
        self.dir.cleanup()

    def _records(self):
        """Snapped record from the review (54 captured of 60), a normal one, and a large orig_len."""
        seg = fx.tcp(40000, 443, fx.TCP_SYN)
        snapped = fx.eth() + fx.ipv4(fx.CLIENT, "10.3.0.1", 6, len(seg)) + seg      # 54 bytes
        return [
            (123, 456789, snapped, 60),
            (124, 1, fx.tcp_packet(fx.CLIENT, "10.3.0.2", 40001, 443, fx.TCP_SYN), 54),
            (4_000_000_000, 999_999, fx.dns_packet(fx.CLIENT, 40002, "a.test"), 1514),
        ]

    def test_review_record_54_of_60_preserved_in_both_engines(self):
        records = self._records()
        fx.write_pcap_records(self.in_path, records)
        for label, make in (("simple", DPIEngine), ("mt", lambda: DPIEngineMT(2, 2))):
            with self.subTest(engine=label):
                out = os.path.join(self.dir.name, f"{label}.pcap")
                _run(make(), self.in_path, out)
                self.assertEqual(fx.read_pcap_records(out), records)
                self.assertEqual(fx.read_pcap_records(out)[0][3], 60)

    def test_metadata_preserved_after_out_of_order_completion(self):
        """Hold the FP that owns record 0 until the other flow finished; order and orig_len must survive."""
        a = fx.tcp_packet(fx.CLIENT, "10.9.0.1", 45000, 443, fx.TCP_ACK)
        ra = route(make_tuple(PacketParser.parse(a)), 1, 2)
        for port in range(46000, 47000):
            b = fx.tcp_packet(fx.CLIENT, "10.9.0.2", port, 443, fx.TCP_ACK)
            if route(make_tuple(PacketParser.parse(b)), 1, 2) != ra:
                break
        records = [(100, 0, a, 300)] + [(101 + i, i, b, 200 + i) for i in range(10)] + [(200, 5, a, 301)]
        fx.write_pcap_records(self.in_path, records)

        b_done = threading.Event()
        seen_b = []

        def hook(fp_id, job):
            if job.packet_id == 0:
                self.assertTrue(b_done.wait(WAIT))
            elif job.tuple.dst_ip == make_tuple(PacketParser.parse(b)).dst_ip:
                seen_b.append(job.packet_id)
                if len(seen_b) == 10:
                    b_done.set()

        eng = DPIEngineMT(1, 2, inspect_hook=hook, queue_size=64)
        out = os.path.join(self.dir.name, "mt.pcap")
        _run(eng, self.in_path, out)
        self.assertEqual(fx.read_pcap_records(out), records)
        self.assertGreaterEqual(eng._writer.max_pending, 10)


if __name__ == "__main__":
    unittest.main()
