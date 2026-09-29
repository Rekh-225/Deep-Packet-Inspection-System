"""
Tests for the multi-threaded engine: routing, ordering, lifecycle, failure
handling, accounting, and equivalence with the single-threaded engine.

Lifecycle tests synchronise with ``threading.Event`` objects through the
engine's ``inspect_hook`` and ``reader_finished`` signals; they never rely on
sleeps for correctness.  Timeouts appear only as upper bounds so a regression
fails instead of hanging.
"""

import contextlib
import io
import os
import tempfile
import threading
import unittest
from unittest import mock

from dpi import engine_mt
from dpi.engine import DPIEngine
from dpi.engine_mt import DPIEngineMT, flow_hash, route
from dpi.inspection import make_tuple
from dpi.packet_parser import PacketParser
from dpi.pcap_io import PcapWriter
from dpi.types import AppType, FiveTuple, ProcessingCancelled, ProcessingError

from tests import fixtures as fx

REPO_PCAP = os.path.join(os.path.dirname(__file__), "..", "test_dpi.pcap")
WAIT = 20.0   # upper bound for any wait; a correct engine never approaches it


def _quiet(fn, *args, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*args, **kwargs)


def _pipeline_threads():
    return [t for t in threading.enumerate() if t.name.startswith(("FP-", "LB-", "Writer"))]


def _tuple_of(packet: bytes) -> FiveTuple:
    return make_tuple(PacketParser.parse(packet))


class MTBase(unittest.TestCase):
    def setUp(self):
        self._paths = []
        self._tmpdir = tempfile.TemporaryDirectory()
        self._counter = 0
        self.assertEqual(_pipeline_threads(), [], "pipeline threads leaked from a previous test")

    def tearDown(self):
        self._tmpdir.cleanup()

    def tmp_path(self, suffix=".pcap"):
        self._counter += 1
        p = os.path.join(self._tmpdir.name, f"f{self._counter}{suffix}")
        self._paths.append(p)
        return p

    def pcap(self, fixture_or_packets):
        packets = getattr(fixture_or_packets, "packets", fixture_or_packets)
        path = self.tmp_path()
        fx.write_pcap(path, packets)
        return path

    def run_engine(self, engine, in_path):
        out = self.tmp_path()
        _quiet(engine.process_file, in_path, out)
        return out

    def run_in_thread(self, engine, in_path):
        out = self.tmp_path()
        result = {}

        def target():
            try:
                _quiet(engine.process_file, in_path, out)
            except BaseException as e:  # noqa: BLE001
                result["error"] = e

        t = threading.Thread(target=target, name="test-runner")
        t.start()
        return t, out, result

    def assert_clean_shutdown(self):
        self.assertEqual(_pipeline_threads(), [], "pipeline threads still alive after process_file")

    def assert_no_output(self, out):
        self.assertFalse(os.path.exists(out), "failed run must not leave an output file")
        leftovers = [f for f in os.listdir(os.path.dirname(out)) if f.endswith(PcapWriter.PARTIAL_SUFFIX)]
        self.assertEqual(leftovers, [], "temporary file(s) must be removed")

    def assert_reconciled(self, engine, fixture, *, forwarded=None, dropped=None):
        s = engine.stats
        self.assertEqual(s.total_packets, fixture.total)
        self.assertEqual(s.unsupported_packets, fixture.unsupported)
        self.assertEqual(s.malformed_packets, fixture.malformed)
        self.assertEqual(s.failed_packets, 0)
        self.assertTrue(s.reconciles(), vars(s))
        if forwarded is not None:
            self.assertEqual(s.forwarded_packets, forwarded)
        if dropped is not None:
            self.assertEqual(s.dropped_packets, dropped)


# =============================================================================
# Routing
# =============================================================================

class TestRouting(unittest.TestCase):
    CONFIGS = [(1, 1), (2, 2), (2, 4), (4, 2), (3, 3), (4, 4), (2, 3)]

    def _tuples(self, n=512):
        return [FiveTuple(0x0A000001, 0x0A000002, 40000 + i, 443, 6) for i in range(n)]

    def test_every_lb_fp_pair_is_reachable(self):
        for lbs, fps in self.CONFIGS:
            seen = {route(t, lbs, fps) for t in self._tuples()}
            expected = {(l, f) for l in range(lbs) for f in range(fps)}
            self.assertEqual(seen, expected, f"config lbs={lbs} fps={fps}")

    def test_distribution_is_not_degenerate(self):
        """No single FP receives more than half of 512 distinct flows in a 2x2 layout."""
        counts = {}
        for t in self._tuples():
            counts[route(t, 2, 2)] = counts.get(route(t, 2, 2), 0) + 1
        self.assertTrue(all(c < 256 for c in counts.values()), counts)

    def test_route_is_direction_independent(self):
        t = FiveTuple(0xC0A80164, 0x08080808, 51000, 53, 17)
        self.assertEqual(flow_hash(t), flow_hash(t.reverse()))
        self.assertEqual(route(t, 3, 2), route(t.reverse(), 3, 2))

    def test_route_distinguishes_protocol(self):
        t6 = FiveTuple(0x0A000001, 0x0A000002, 40000, 443, 6)
        t17 = FiveTuple(0x0A000001, 0x0A000002, 40000, 443, 17)
        self.assertNotEqual(flow_hash(t6), flow_hash(t17))

    def test_flow_hash_is_stable(self):
        """Pinned regression value produced by this implementation (crc32 of the canonical tuple);
        it is not an independent expectation, it guards against accidental routing changes."""
        t = FiveTuple(0x0A000001, 0x0A000002, 40000, 443, 6)
        import struct, zlib
        expected = zlib.crc32(struct.pack("!IHIHB", 0x0A000001, 40000, 0x0A000002, 443, 6))
        self.assertEqual(flow_hash(t), expected)
        self.assertEqual(flow_hash(t), 0x3E3C17E9)


# =============================================================================
# Equivalence with the single-threaded engine
# =============================================================================

def _rule_sets():
    return {
        "none": lambda e: None,
        "ip": lambda e: e.block_ip(fx.BLOCKED_CLIENT),
        "app_youtube": lambda e: e.block_app("YouTube"),
        "domain_dns": lambda e: e.block_domain("www.google.com"),
        "domain_http": lambda e: e.block_domain("httpbin"),
        "wildcard": lambda e: e.block_domain("*.twitter.com"),
        "port_53": lambda e: e.block_port(53),
        "all": lambda e: (e.block_ip(fx.BLOCKED_CLIENT), e.block_app("Netflix"),
                          e.block_domain("example"), e.block_port(53)),
    }


class TestEquivalence(MTBase):
    def _compare(self, fixture, apply_rules, lbs, fps, expected_dropped=None):
        path = self.pcap(fixture)
        simple = DPIEngine()
        apply_rules(simple)
        out_s = self.run_engine(simple, path)

        mt = DPIEngineMT(num_lbs=lbs, fps_per_lb=fps)
        apply_rules(mt)
        out_m = self.run_engine(mt, path)
        self.assert_clean_shutdown()

        self.assertEqual(vars(mt.stats), vars(simple.stats))
        self.assertEqual(dict(mt._app_stats), dict(simple._app_stats))
        self.assertEqual(mt._detected_snis, simple._detected_snis)
        self.assertEqual(fx.read_pcap(out_m), fx.read_pcap(out_s))
        self.assert_reconciled(mt, fixture, dropped=expected_dropped)
        return simple, mt

    def test_all_rule_sets_all_layouts(self):
        for name, rules in _rule_sets().items():
            for lbs, fps in ((1, 1), (2, 2), (3, 2)):
                with self.subTest(rules=name, lbs=lbs, fps=fps):
                    self._compare(fx.mixed_supported_fixture(), rules, lbs, fps)

    def test_unsupported_fixture_all_layouts(self):
        for lbs, fps in ((1, 1), (2, 2)):
            with self.subTest(lbs=lbs, fps=fps):
                self._compare(fx.mixed_with_unsupported_fixture(), _rule_sets()["all"], lbs, fps)

    def test_dns_domain_rule_blocks_the_query(self):
        """Domain rule matches the DNS query name (1) and the TLS Client Hello (1) for www.google.com."""
        self._compare(fx.mixed_supported_fixture(), _rule_sets()["domain_dns"], 2, 2, expected_dropped=2)

    def test_http_host_rule(self):
        """'httpbin' matches only the GET packet; the preceding SYN has no Host header."""
        self._compare(fx.mixed_supported_fixture(), _rule_sets()["domain_http"], 2, 2, expected_dropped=1)

    def test_tls_app_rule(self):
        """YouTube is identified on the Client Hello; SYN/ACK before it are not blocked."""
        self._compare(fx.mixed_supported_fixture(), _rule_sets()["app_youtube"], 2, 2, expected_dropped=1)

    def test_ip_rule(self):
        self._compare(fx.mixed_supported_fixture(), _rule_sets()["ip"], 2, 2, expected_dropped=5)

    def test_port_rule_blocks_all_dns(self):
        self._compare(fx.mixed_supported_fixture(), _rule_sets()["port_53"], 2, 2, expected_dropped=3)

    def test_repo_fixture_ip_block(self):
        """test_dpi.pcap (generated by generate_test_pcap.py): 5 packets from 192.168.1.50."""
        simple = DPIEngine(); simple.block_ip("192.168.1.50")
        out_s = self.run_engine(simple, REPO_PCAP)
        mt = DPIEngineMT(2, 2); mt.block_ip("192.168.1.50")
        out_m = self.run_engine(mt, REPO_PCAP)
        self.assertEqual(simple.stats.dropped_packets, 5)
        self.assertEqual(vars(mt.stats), vars(simple.stats))
        self.assertEqual(fx.read_pcap(out_m), fx.read_pcap(out_s))


# =============================================================================
# Accounting
# =============================================================================

class TestAccounting(MTBase):
    def test_no_rules_retains_every_supported_packet(self):
        fixture = fx.mixed_supported_fixture()
        eng = DPIEngineMT(2, 2)
        out = self.run_engine(eng, self.pcap(fixture))
        self.assert_reconciled(eng, fixture, forwarded=fixture.total, dropped=0)
        self.assertEqual(fx.read_pcap(out), fixture.packets)

    def test_unsupported_and_malformed_are_counted_and_excluded(self):
        fixture = fx.mixed_with_unsupported_fixture()
        eng = DPIEngineMT(2, 2)
        out = self.run_engine(eng, self.pcap(fixture))
        self.assert_reconciled(eng, fixture, forwarded=fixture.supported, dropped=0)
        self.assertEqual(eng.stats.total_packets, 48)
        self.assertEqual(eng.stats.unsupported_packets, 3)
        self.assertEqual(eng.stats.malformed_packets, 1)
        # Output is exactly the supported packets, in input order.
        self.assertEqual(fx.read_pcap(out), fx.mixed_supported_fixture().packets)

    def test_all_blocked_produces_empty_valid_pcap(self):
        fixture = fx.many_flows_fixture(16, 2)
        eng = DPIEngineMT(2, 2)
        eng.block_ip(fx.CLIENT)
        out = self.run_engine(eng, self.pcap(fixture))
        self.assert_reconciled(eng, fixture, forwarded=0, dropped=fixture.total)
        self.assertEqual(fx.read_pcap(out), [])
        self.assertEqual(os.path.getsize(out), 24)

    def test_per_thread_counts_sum_to_supported(self):
        fixture = fx.mixed_with_unsupported_fixture()
        eng = DPIEngineMT(2, 2)
        self.run_engine(eng, self.pcap(fixture))
        self.assertEqual(sum(fp.processed for fp in eng._fps), fixture.supported)
        self.assertEqual(sum(lb.dispatched for lb in eng._lbs), fixture.supported)

    def test_all_fast_paths_receive_work_2x2(self):
        eng = DPIEngineMT(2, 2)
        self.run_engine(eng, self.pcap(fx.many_flows_fixture(64)))
        processed = [fp.processed for fp in eng._fps]
        self.assertTrue(all(n > 0 for n in processed), processed)

    def test_all_fast_paths_receive_work_2x4(self):
        eng = DPIEngineMT(2, 4)
        self.run_engine(eng, self.pcap(fx.many_flows_fixture(128)))
        processed = [fp.processed for fp in eng._fps]
        self.assertTrue(all(n > 0 for n in processed), processed)

    def test_flow_affinity(self):
        """Every packet of a flow is processed by exactly one FP; both directions share it."""
        fixture = fx.mixed_supported_fixture()
        owner = {}
        conflicts = []
        lock = threading.Lock()

        def hook(fp_id, job):
            key = flow_hash(job.tuple)
            with lock:
                prev = owner.setdefault(key, fp_id)
                if prev != fp_id:
                    conflicts.append((job.packet_id, prev, fp_id))

        eng = DPIEngineMT(2, 2, inspect_hook=hook)
        self.run_engine(eng, self.pcap(fixture))
        self.assertEqual(conflicts, [])
        self.assertGreater(len(owner), 1)

    def test_uneven_flows(self):
        fixture = fx.uneven_flows_fixture(hot_packets=300, cold_flows=5)
        eng = DPIEngineMT(2, 2, queue_size=16)
        out = self.run_engine(eng, self.pcap(fixture))
        self.assert_reconciled(eng, fixture, forwarded=fixture.total)
        self.assertEqual(fx.read_pcap(out), fixture.packets)
        self.assertEqual(sum(1 for fp in eng._fps if fp.processed >= 300), 1, "hot flow must stay on one FP")


# =============================================================================
# Ordering, backpressure, lifecycle
# =============================================================================

class TestLifecycle(MTBase):
    def _two_flows_on_different_fps(self, lbs, fps, per_flow=20):
        """Flow A (packet 0) and flow B routed to different FPs; B's packets interleaved after A's first."""
        a = [fx.tcp_packet(fx.CLIENT, "10.9.0.1", 45000, 443, fx.TCP_ACK) for _ in range(per_flow)]
        route_a = route(_tuple_of(a[0]), lbs, fps)
        for port in range(46000, 47000):
            b = [fx.tcp_packet(fx.CLIENT, "10.9.0.2", port, 443, fx.TCP_ACK) for _ in range(per_flow)]
            if route(_tuple_of(b[0]), lbs, fps) != route_a:
                break
        else:
            self.fail("could not find two flows on different FPs")
        packets = [a[0]] + b + a[1:]
        return packets, route_a

    def test_output_preserves_input_order_with_slow_worker(self):
        """Hold packet 0 until flow B has been fully processed by the other FP; output must be in input order."""
        packets, _ = self._two_flows_on_different_fps(1, 2)
        b_done = threading.Event()
        b_seen = []

        def hook(fp_id, job):
            if job.packet_id == 0:
                self.assertTrue(b_done.wait(WAIT), "flow B never finished")
            elif job.tuple.dst_ip == _tuple_of(packets[1]).dst_ip:
                b_seen.append(job.packet_id)
                if len(b_seen) == 20:
                    b_done.set()

        eng = DPIEngineMT(1, 2, inspect_hook=hook, queue_size=64)
        out = self.run_engine(eng, self.pcap(packets))
        self.assert_clean_shutdown()
        self.assertEqual(fx.read_pcap(out), packets)
        self.assertEqual(eng.stats.forwarded_packets, len(packets))
        self.assertGreaterEqual(eng._writer.max_pending, 20)

    def test_slow_worker_is_waited_for_not_abandoned(self):
        """Reader finishes and the run stays open until the gated worker completes; nothing is lost."""
        fixture = fx.uneven_flows_fixture(hot_packets=50, cold_flows=0)
        reached, gate = threading.Event(), threading.Event()

        def hook(fp_id, job):
            if job.packet_id == 0:
                reached.set()
                self.assertTrue(gate.wait(WAIT))

        eng = DPIEngineMT(1, 1, inspect_hook=hook, queue_size=1000)
        t, out, result = self.run_in_thread(eng, self.pcap(fixture))
        self.assertTrue(reached.wait(WAIT))
        self.assertTrue(eng.reader_finished.wait(WAIT), "reader should finish while FP is gated")
        self.assertTrue(t.is_alive(), "engine returned before its worker finished")
        self.assertFalse(os.path.exists(out))
        gate.set()
        t.join(WAIT)
        self.assertFalse(t.is_alive())
        self.assertNotIn("error", result)
        self.assert_clean_shutdown()
        self.assert_reconciled(eng, fixture, forwarded=fixture.total)
        self.assertEqual(fx.read_pcap(out), fixture.packets)

    def test_input_larger_than_queue_capacity(self):
        fixture = fx.many_flows_fixture(64, 4)     # 256 packets
        eng = DPIEngineMT(2, 2, queue_size=4)
        out = self.run_engine(eng, self.pcap(fixture))
        self.assert_reconciled(eng, fixture, forwarded=fixture.total)
        self.assertEqual(fx.read_pcap(out), fixture.packets)
        self.assertLessEqual(eng._writer.max_pending, 4)

    def test_reorder_buffer_is_bounded_by_window(self):
        """With packet 0 held, the reader must stop after queue_size admissions; the buffer never exceeds it."""
        packets, _ = self._two_flows_on_different_fps(1, 2, per_flow=100)
        gate, reached = threading.Event(), threading.Event()

        def hook(fp_id, job):
            if job.packet_id == 0:
                reached.set()
                self.assertTrue(gate.wait(WAIT))

        eng = DPIEngineMT(1, 2, inspect_hook=hook, queue_size=8)
        t, out, result = self.run_in_thread(eng, self.pcap(packets))
        self.assertTrue(reached.wait(WAIT))
        # Wait until the window is exhausted: the other FP has then processed at most 7 packets
        # and the reader is blocked.  Observe via the writer's pending buffer reaching 7.
        deadline_ok = self._wait_until(lambda: len(eng._writer.pending) >= 7)
        self.assertTrue(deadline_ok)
        self.assertFalse(eng.reader_finished.is_set(), "reader must be blocked by backpressure")
        self.assertLessEqual(len(eng._writer.pending), 8)
        gate.set()
        t.join(WAIT)
        self.assertNotIn("error", result)
        self.assertLessEqual(eng._writer.max_pending, 8)
        self.assertEqual(fx.read_pcap(out), packets)

    @staticmethod
    def _wait_until(predicate, timeout=WAIT):
        import time
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if predicate():
                return True
            time.sleep(0.005)
        return predicate()

    def test_no_pipeline_threads_remain_after_success(self):
        eng = DPIEngineMT(2, 2)
        self.run_engine(eng, self.pcap(fx.mixed_supported_fixture()))
        self.assert_clean_shutdown()

    def test_single_fp_layout(self):
        fixture = fx.mixed_with_unsupported_fixture()
        eng = DPIEngineMT(1, 1)
        out = self.run_engine(eng, self.pcap(fixture))
        self.assert_reconciled(eng, fixture, forwarded=fixture.supported)
        self.assertEqual(fx.read_pcap(out), fx.mixed_supported_fixture().packets)

    def test_empty_input(self):
        eng = DPIEngineMT(2, 2)
        out = self.run_engine(eng, self.pcap([]))
        self.assertEqual(eng.stats.total_packets, 0)
        self.assertEqual(fx.read_pcap(out), [])


# =============================================================================
# Failures and cancellation
# =============================================================================

class TestFailures(MTBase):
    def test_worker_exception_fails_run_and_discards_output(self):
        fixture = fx.mixed_supported_fixture()

        def hook(fp_id, job):
            if job.packet_id == 5:
                raise RuntimeError("injected")

        eng = DPIEngineMT(2, 2, inspect_hook=hook)
        out = self.tmp_path()
        with self.assertRaises(ProcessingError) as cm:
            _quiet(eng.process_file, self.pcap(fixture), out)
        self.assertIn("injected", str(cm.exception))
        self.assertIsInstance(cm.exception.__cause__, RuntimeError)
        self.assert_no_output(out)
        self.assert_clean_shutdown()
        self.assertGreater(eng.stats.failed_packets, 0)
        self.assertTrue(eng.stats.reconciles(), vars(eng.stats))
        self.assertEqual(len(eng.errors), 1)
        self.assertTrue(eng.errors[0][0].startswith("FP-"), eng.errors)

    def test_worker_exception_with_full_queues_does_not_deadlock(self):
        fixture = fx.many_flows_fixture(64, 8)    # 512 packets, queue_size 2

        def hook(fp_id, job):
            if job.packet_id == 10:
                raise ValueError("injected at 10")

        eng = DPIEngineMT(2, 2, inspect_hook=hook, queue_size=2)
        t, out, result = self.run_in_thread(eng, self.pcap(fixture))
        t.join(WAIT)
        self.assertFalse(t.is_alive(), "pipeline deadlocked after worker failure")
        self.assertIsInstance(result.get("error"), ProcessingError)
        self.assert_no_output(out)
        self.assert_clean_shutdown()
        self.assertTrue(eng.stats.reconciles())

    def test_writer_failure_unwinds_pipeline(self):
        fixture = fx.many_flows_fixture(64, 4)

        def failing_write(self_w, ts_sec, ts_usec, data, orig_len=None):
            raise OSError("disk full (injected)")

        eng = DPIEngineMT(2, 2, queue_size=4)
        out = self.tmp_path()
        with mock.patch.object(PcapWriter, "write_packet", failing_write):
            with self.assertRaises(ProcessingError) as cm:
                _quiet(eng.process_file, self.pcap(fixture), out)
        self.assertIn("Writer", str(cm.exception))
        self.assertIn("disk full", str(cm.exception))
        self.assert_no_output(out)
        self.assert_clean_shutdown()

    def test_reader_failure_unwinds_pipeline(self):
        fixture = fx.many_flows_fixture(32, 4)
        eng = DPIEngineMT(2, 2, queue_size=4)
        out = self.tmp_path()
        calls = {"n": 0}
        original = PacketParser.parse

        def flaky_parse(data, ts_sec=0, ts_usec=0):
            calls["n"] += 1
            if calls["n"] == 40:
                raise RuntimeError("parser exploded")
            return original(data, ts_sec=ts_sec, ts_usec=ts_usec)

        with mock.patch.object(PacketParser, "parse", staticmethod(flaky_parse)):
            with self.assertRaises(ProcessingError) as cm:
                _quiet(eng.process_file, self.pcap(fixture), out)
        self.assertIn("Reader", str(cm.exception))
        self.assert_no_output(out)
        self.assert_clean_shutdown()

    def test_cancel_from_worker(self):
        fixture = fx.many_flows_fixture(64, 4)

        def hook(fp_id, job):
            if job.packet_id == 3:
                eng.cancel()

        eng = DPIEngineMT(2, 2, inspect_hook=hook, queue_size=4)
        out = self.tmp_path()
        with self.assertRaises(ProcessingCancelled):
            _quiet(eng.process_file, self.pcap(fixture), out)
        self.assert_no_output(out)
        self.assert_clean_shutdown()
        self.assertTrue(eng.stats.reconciles())

    def test_cancel_while_worker_blocked(self):
        """cancel() from another thread while an FP is busy: the FP observes `stopping` and unwinds."""
        fixture = fx.uneven_flows_fixture(hot_packets=40, cold_flows=0)
        reached = threading.Event()

        def hook(fp_id, job):
            if job.packet_id == 0:
                reached.set()
                self.assertTrue(eng.stopping.wait(WAIT))

        eng = DPIEngineMT(1, 1, inspect_hook=hook, queue_size=8)
        t, out, result = self.run_in_thread(eng, self.pcap(fixture))
        self.assertTrue(reached.wait(WAIT))
        eng.cancel()
        t.join(WAIT)
        self.assertFalse(t.is_alive())
        self.assertIsInstance(result.get("error"), ProcessingCancelled)
        self.assert_no_output(out)
        self.assert_clean_shutdown()

    def test_cancelled_engine_refuses_to_run(self):
        eng = DPIEngineMT(1, 1)
        eng.cancel()
        with self.assertRaises(ProcessingCancelled):
            _quiet(eng.process_file, self.pcap(fx.many_flows_fixture(2, 1)), self.tmp_path())

    def test_missing_input_raises(self):
        eng = DPIEngineMT(1, 1)
        out = self.tmp_path()
        with self.assertRaises(ProcessingError):
            _quiet(eng.process_file, os.path.join(tempfile.gettempdir(), "does-not-exist.pcap"), out)
        self.assert_no_output(out)
        self.assert_clean_shutdown()

    def test_unwritable_output_raises(self):
        eng = DPIEngineMT(1, 1)
        bad_out = os.path.join(tempfile.gettempdir(), "no-such-dir-dpi", "out.pcap")
        with self.assertRaises(ProcessingError):
            _quiet(eng.process_file, self.pcap(fx.many_flows_fixture(2, 1)), bad_out)
        self.assert_clean_shutdown()

    def test_invalid_layout_rejected(self):
        with self.assertRaises(ValueError):
            DPIEngineMT(0, 2)
        with self.assertRaises(ValueError):
            DPIEngineMT(2, 0)
        with self.assertRaises(ValueError):
            DPIEngineMT(1, 1, queue_size=0)


if __name__ == "__main__":
    unittest.main()
