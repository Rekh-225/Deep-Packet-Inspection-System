"""
Review finding 1: flow-state capacity must not depend on engine topology.

Both engines share one global ``max_flows`` limit.  Below and at the limit
they produce identical output; beyond it both fail with
``FlowCapacityExceeded`` (no silent eviction, no committed output).
"""

import contextlib
import glob
import io
import os
import tempfile
import unittest

from dpi.engine import DPIEngine
from dpi.engine_mt import DPIEngineMT
from dpi.types import FlowCapacity, FlowCapacityExceeded, ProcessingError

from tests import fixtures as fx

LAYOUTS = ((1, 1), (2, 2), (2, 4))


def _run(engine, in_path, out_path):
    with contextlib.redirect_stdout(io.StringIO()):
        engine.process_file(in_path, out_path)


class CapacityBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.dir.cleanup()

    def pcap(self, packets, name="in.pcap"):
        p = os.path.join(self.dir.name, name)
        fx.write_pcap(p, packets)
        return p

    def engines(self, max_flows):
        yield "simple", lambda: DPIEngine(max_flows=max_flows)
        for lbs, fps in LAYOUTS:
            yield f"mt {lbs}x{fps}", lambda lbs=lbs, fps=fps: DPIEngineMT(lbs, fps, max_flows=max_flows)

    def assert_no_leftovers(self, out):
        self.assertFalse(os.path.exists(out))
        self.assertEqual(glob.glob(os.path.join(os.path.dirname(out), ".*partial*")), [])


class TestFlowCapacityUnit(unittest.TestCase):
    def test_acquire_until_limit_then_fail(self):
        cap = FlowCapacity(3)
        for _ in range(3):
            cap.acquire()
        with self.assertRaises(FlowCapacityExceeded) as cm:
            cap.acquire()
        self.assertIn("maximum is 3", str(cm.exception))
        self.assertEqual(cap.count, 3)

    def test_invalid_limit(self):
        with self.assertRaises(ValueError):
            FlowCapacity(0)
        with self.assertRaises(ValueError):
            DPIEngine(max_flows=0)
        with self.assertRaises(ValueError):
            DPIEngineMT(1, 1, max_flows=0)


class TestBelowAtBeyond(CapacityBase):
    FLOWS = 12

    def _outputs(self, max_flows, packets):
        in_path = self.pcap(packets)
        results = {}
        for label, make in self.engines(max_flows):
            out = os.path.join(self.dir.name, f"{label.replace(' ', '_')}.pcap")
            eng = make()
            try:
                _run(eng, in_path, out)
                with open(out, "rb") as f:
                    results[label] = ("ok", vars(eng.stats).copy(), f.read())
            except ProcessingError as e:
                self.assert_no_leftovers(out)
                results[label] = ("fail", type(e).__name__, "maximum is %d" % max_flows in str(e))
        return results

    def test_below_capacity_all_layouts_identical(self):
        pk = fx.many_flows_fixture(self.FLOWS, 2).packets
        res = self._outputs(self.FLOWS + 5, pk)
        ref = res["simple"]
        self.assertEqual(ref[0], "ok")
        for label, r in res.items():
            self.assertEqual(r, ref, label)

    def test_exactly_at_capacity_succeeds_identically(self):
        pk = fx.many_flows_fixture(self.FLOWS, 2).packets
        res = self._outputs(self.FLOWS, pk)
        for label, r in res.items():
            self.assertEqual(r[0], "ok", label)
            self.assertEqual(r, res["simple"], label)
        self.assertEqual(res["simple"][1]["forwarded_packets"], self.FLOWS * 2)

    def test_one_beyond_capacity_fails_consistently(self):
        pk = fx.many_flows_fixture(self.FLOWS, 2).packets
        res = self._outputs(self.FLOWS - 1, pk)
        for label, r in res.items():
            self.assertEqual(r, ("fail", "FlowCapacityExceeded", True), label)

    def test_reverse_direction_counts_as_its_own_flow_in_every_layout(self):
        """4 TLS flows have 4 reverse flows: 8 flows total; a limit of 7 fails everywhere, 8 succeeds."""
        pk = []
        for i in range(4):
            pk += fx.tls_flow(fx.CLIENT, "10.5.0.1", 43000 + i, "github.com")
        for label, r in self._outputs(7, pk).items():
            self.assertEqual(r[0], "fail", label)
        for label, r in self._outputs(8, pk).items():
            self.assertEqual(r[0], "ok", label)


class TestReviewReproduction(CapacityBase):
    """
    The review's 100,002-packet case: a YouTube Client Hello (blocked), 100,000
    distinct intervening flows, then a second packet of the YouTube flow.

    Before the fix, the simple engine evicted the blocked flow at its per-tracker
    limit of 100,000 and forwarded the last packet, while MT (with a separate
    limit per fast path) kept the state and filtered it.
    """

    N = 100_000

    def _packets(self):
        pk = [fx.tcp_packet(fx.CLIENT, "10.7.0.1", 40000, 443, fx.TCP_PSH | fx.TCP_ACK,
                            fx.tls_client_hello("www.youtube.com"))]
        # 100,000 distinct flows: vary destination IP and source port.
        for i in range(self.N):
            dst = f"10.8.{(i >> 8) & 255}.{i & 255}"
            pk.append(fx.tcp_packet(fx.CLIENT, dst, 1024 + (i % 60000), 443, fx.TCP_SYN))
        pk.append(fx.tcp_packet(fx.CLIENT, "10.7.0.1", 40000, 443, fx.TCP_ACK))
        self.assertEqual(len(pk), self.N + 2)
        return pk

    def test_100002_packets_same_result_in_both_engines(self):
        in_path = self.pcap(self._packets())
        outcomes = {}
        for max_flows in (self.N + 1, self.N):          # exactly enough / one short
            for label, make in (("simple", lambda: DPIEngine(max_flows=max_flows)),
                                ("mt 2x2", lambda: DPIEngineMT(2, 2, max_flows=max_flows))):
                eng = make()
                eng.block_app("YouTube")
                out = os.path.join(self.dir.name, f"{label.replace(' ', '_')}-{max_flows}.pcap")
                try:
                    _run(eng, in_path, out)
                    with open(out, "rb") as f:
                        outcomes[(max_flows, label)] = ("ok", eng.stats.forwarded_packets,
                                                        eng.stats.dropped_packets, f.read())
                except FlowCapacityExceeded:
                    self.assert_no_leftovers(out)
                    outcomes[(max_flows, label)] = ("fail",)

        ok_s, ok_m = outcomes[(self.N + 1, "simple")], outcomes[(self.N + 1, "mt 2x2")]
        self.assertEqual(ok_s[0], "ok")
        self.assertEqual(ok_s, ok_m)
        self.assertEqual((ok_s[1], ok_s[2]), (self.N, 2), "both YouTube packets must be filtered")
        self.assertEqual(outcomes[(self.N, "simple")], ("fail",))
        self.assertEqual(outcomes[(self.N, "mt 2x2")], ("fail",))


if __name__ == "__main__":
    unittest.main()
