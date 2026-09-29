"""
Review finding 8: detection and blocked-flow history is bounded by
``max_report_detail`` in both engines, truncation is shown, aggregate counts
stay exact, and report generation streams flows instead of materialising them.

Review finding 9: a report failure after a committed capture is a distinct,
documented outcome (exit 3, "capture completed; report failed"), the capture is
preserved, and no partial report is left behind.
"""

import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from dpi import report as rp
from dpi.cli import EXIT_OK, EXIT_PROCESSING_FAILED, EXIT_REPORT_FAILED, main as cli_main
from dpi.engine import DPIEngine
from dpi.engine_mt import DPIEngineMT

from tests import fixtures as fx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE = os.path.join(ROOT, "samples", "captures", "mixed_supported.pcap")


def _detections_capture(path, n=40):
    """n TLS Client Hellos with distinct names to distinct servers; every one is blocked by 'site'."""
    pkts = []
    for i in range(n):
        pkts.append(fx.tcp_packet(fx.CLIENT, f"10.11.{i // 250}.{i % 250 + 1}", 40000 + i, 443,
                                  fx.TCP_PSH | fx.TCP_ACK, fx.tls_client_hello(f"site{i}.example")))
    fx.write_pcap(path, pkts)
    return pkts


class TestBoundedDetail(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.in_path = os.path.join(self.dir.name, "in.pcap")
        self.out = os.path.join(self.dir.name, "out.pcap")
        _detections_capture(self.in_path, 40)

    def tearDown(self):
        self.dir.cleanup()

    def _run(self, eng):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            eng.process_file(self.in_path, self.out)
        return buf.getvalue()

    def test_detail_bounded_in_both_engines_with_exact_aggregates(self):
        for label, make in (("simple", lambda: DPIEngine(max_report_detail=5)),
                            ("mt", lambda: DPIEngineMT(2, 2, max_report_detail=5))):
            with self.subTest(engine=label):
                eng = make()
                eng.block_domain("site")
                console = self._run(eng)
                self.assertEqual(len(eng.detections.items), 5)
                self.assertEqual(eng.detections.total, 40)
                self.assertEqual(eng.detections.dropped, 35)
                self.assertTrue(eng.detections.truncated)
                self.assertIn("35 further detection(s) not listed", console)
                self.assertEqual(eng.stats.dropped_packets, 40)           # aggregates unaffected
                self.assertEqual(eng.flow_count, 40)
                self.assertEqual(eng.app_stats[list(eng.app_stats)[0]], 40)
                if label == "mt":
                    self.assertLessEqual(len(eng._blocked_flows), 5)
                    self.assertEqual(len(eng._blocked_flows) + eng._blocked_dropped, 40)
                    self.assertIn("further blocked flow(s) not listed", console)
                    for fp in eng._fps:
                        self.assertLessEqual(len(fp.detections), 5)
                        self.assertLessEqual(len(fp.blocked_flows), 5)

    def test_detail_growth_stays_within_limit_as_input_grows(self):
        """Doubling the input must not grow the retained detail past the limit."""
        sizes = {}
        for n in (20, 80):
            _detections_capture(self.in_path, n)
            eng = DPIEngineMT(1, 2, max_report_detail=8)
            self._run(eng)
            sizes[n] = (len(eng.detections.items), sum(len(fp.detections) for fp in eng._fps), eng.detections.total)
        self.assertEqual(sizes[20][0], 8)
        self.assertEqual(sizes[80][0], 8)
        self.assertLessEqual(sizes[80][1], 16)          # 2 FPs x limit
        self.assertEqual((sizes[20][2], sizes[80][2]), (20, 80))

    def test_zero_detail_keeps_counts(self):
        eng = DPIEngine(max_report_detail=0)
        self._run(eng)
        self.assertEqual(eng.detections.items, {})
        self.assertEqual(eng.detections.total, 40)

    def test_report_shows_detail_truncation_and_streams_flows(self):
        eng = DPIEngineMT(2, 2, max_report_detail=3)
        self._run(eng)
        with mock.patch.object(eng, "connections", wraps=eng.connections) as spy:
            r = rp.build_report(eng, self.in_path, self.out, max_flows=4)
        # aggregates in one pass + one bounded-heap pass; never list(all flows)
        self.assertEqual(spy.call_count, 2)
        self.assertEqual(r["flows"]["total"], 40)
        self.assertEqual(r["flows"]["listed"], 4)
        self.assertTrue(r["flows"]["truncated"])
        self.assertEqual([f["first_packet_id"] for f in r["flows"]["items"]], [0, 1, 2, 3])
        self.assertEqual(r["detail"], {"limit": 3, "detections_total": 40, "detections_listed": 3,
                                       "detections_truncated": True})

    def test_simple_and_mt_reports_identical_under_bounds(self):
        a = DPIEngine(max_report_detail=6); b = DPIEngineMT(2, 2, max_report_detail=6)
        for e in (a, b):
            e.block_domain("site1")
            self._run(e)
        ra = rp.build_report(a, self.in_path, self.out, max_flows=10)
        rb = rp.build_report(b, self.in_path, self.out, max_flows=10)
        for r in (ra, rb):
            r["run"].pop("mode"); r["run"].pop("threads", None)
        self.assertEqual(ra, rb)
        self.assertEqual(a.detections.items, b.detections.items)


class TestReportFailureContract(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.out = os.path.join(self.dir.name, "out.pcap")

    def tearDown(self):
        self.dir.cleanup()

    def _cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli_main([SAMPLE, self.out, *args])
        return rc, out.getvalue(), err.getvalue()

    def _partials(self):
        return [f for f in os.listdir(self.dir.name) if f.endswith(".partial")]

    def test_unwritable_report_dir_is_exit_3_and_capture_kept(self):
        bad = os.path.join(self.dir.name, "no", "dir", "r.json")
        rc, out, err = self._cli("--mode", "mt", "--report-json", bad)
        self.assertEqual(rc, EXIT_REPORT_FAILED)
        self.assertTrue(os.path.exists(self.out))
        self.assertEqual(len(fx.read_pcap(self.out)), 44)
        self.assertIn("capture completed; report failed", err)
        self.assertIn("capture:      written", err)
        self.assertIn("JSON report:  FAILED", err)
        self.assertIn(bad, err)
        self.assertFalse(os.path.exists(bad))

    def test_json_ok_html_fails_lists_both(self):
        good = os.path.join(self.dir.name, "r.json")
        bad = os.path.join(self.dir.name, "no", "r.html")
        rc, out, err = self._cli("--report-json", good, "--report-html", bad)
        self.assertEqual(rc, EXIT_REPORT_FAILED)
        self.assertTrue(os.path.exists(good))
        with open(good, encoding="utf-8") as f:
            json.load(f)
        self.assertIn("JSON report:  written", err)
        self.assertIn("HTML report:  FAILED", err)
        self.assertEqual(self._partials(), [])

    def test_injected_html_write_failure(self):
        html_path = os.path.join(self.dir.name, "r.html")
        with mock.patch.object(rp, "write_html", side_effect=OSError("disk full (injected)")):
            rc, out, err = self._cli("--report-html", html_path)
        self.assertEqual(rc, EXIT_REPORT_FAILED)
        self.assertIn("disk full", err)
        self.assertTrue(os.path.exists(self.out))
        self.assertFalse(os.path.exists(html_path))

    def test_report_build_exception_is_report_failure_not_processing_failure(self):
        path = os.path.join(self.dir.name, "r.json")
        with mock.patch.object(rp, "build_report", side_effect=RuntimeError("boom")):
            rc, out, err = self._cli("--report-json", path)
        self.assertEqual(rc, EXIT_REPORT_FAILED)
        self.assertNotEqual(rc, EXIT_PROCESSING_FAILED)
        self.assertIn("RuntimeError: boom", err)
        self.assertTrue(os.path.exists(self.out))

    def test_no_partial_report_is_left_when_replace_fails(self):
        path = os.path.join(self.dir.name, "r.json")
        real_replace = os.replace

        def replace_reports_only(src, dst):
            if dst.endswith(".json"):
                raise OSError("replace denied (injected)")
            return real_replace(src, dst)

        with mock.patch("dpi.report.os.replace", side_effect=replace_reports_only):
            rc, out, err = self._cli("--report-json", path)
        self.assertEqual(rc, EXIT_REPORT_FAILED)
        self.assertFalse(os.path.exists(path))
        self.assertEqual(self._partials(), [])
        self.assertIn("replace denied", err)

    def test_report_written_atomically_on_success(self):
        path = os.path.join(self.dir.name, "r.json")
        html = os.path.join(self.dir.name, "r.html")
        rc, out, err = self._cli("--report-json", path, "--report-html", html, "--report-no-timestamp")
        self.assertEqual(rc, EXIT_OK)
        self.assertEqual(self._partials(), [])
        self.assertTrue(os.path.exists(path) and os.path.exists(html))
        self.assertIn("JSON report written", out)

    def test_processing_failure_still_exit_1_without_reports(self):
        rc, out, err = self._cli("--report-json", os.path.join(self.dir.name, "r.json"), "--max-flows", "3")
        self.assertEqual(rc, EXIT_PROCESSING_FAILED)
        self.assertFalse(os.path.exists(self.out))
        self.assertFalse(os.path.exists(os.path.join(self.dir.name, "r.json")))
        self.assertIn("flow limit reached", err)


if __name__ == "__main__":
    unittest.main()
