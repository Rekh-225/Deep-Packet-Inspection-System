"""
Sample captures: reproducible generation, by-construction expectations for
both engines, and predictable rejection of unsupported / malformed input.
"""

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

from dpi.engine import DPIEngine
from dpi.engine_mt import DPIEngineMT
from dpi.types import ProcessingError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "samples")
CAPTURES = os.path.join(SAMPLES, "captures")
CLI = os.path.join(ROOT, "cli.py")

with open(os.path.join(SAMPLES, "expected.json"), encoding="utf-8") as _f:
    EXPECTED = json.load(_f)


def run_cli(*args):
    return subprocess.run(
        [sys.executable, CLI, *args], cwd=ROOT, capture_output=True, timeout=120,
        encoding="utf-8", errors="replace",
    )


def _apply_args(engine, args):
    """Apply the CLI-style args from expected.json to an engine object."""
    it = iter(args)
    for flag in it:
        value = next(it)
        if flag == "--rules-file":
            assert engine.load_rules(os.path.join(ROOT, value))
        elif flag == "--block-domain":
            engine.block_domain(value)
        elif flag == "--block-ip":
            engine.block_ip(value)
        elif flag == "--block-app":
            engine.block_app(value)
        elif flag == "--block-port":
            engine.block_port(int(value))
        else:
            raise AssertionError(flag)


class TestSampleGeneration(unittest.TestCase):
    def test_samples_regenerate_byte_identical(self):
        r = subprocess.run([sys.executable, os.path.join(SAMPLES, "make_samples.py"), "--check"],
                           cwd=ROOT, capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_every_capture_has_an_expectation(self):
        listed = set(EXPECTED["captures"]) | set(EXPECTED["rejected"])
        on_disk = {f for f in os.listdir(CAPTURES) if not f.startswith(".")}
        self.assertEqual(on_disk, listed)


class TestSampleExpectations(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.dir.cleanup()

    def _run(self, engine, capture):
        out = os.path.join(self.dir.name, "out.pcap")
        with contextlib.redirect_stdout(io.StringIO()):
            engine.process_file(os.path.join(CAPTURES, capture), out)
        return out

    def test_accepted_captures_match_expectations_in_both_engines(self):
        for capture, exp in EXPECTED["captures"].items():
            for run_name, run in exp["runs"].items():
                for make in (DPIEngine, lambda: DPIEngineMT(2, 2)):
                    eng = make()
                    _apply_args(eng, run["args"])
                    with self.subTest(capture=capture, run=run_name, mode=eng.mode):
                        self._run(eng, capture)
                        s = eng.stats
                        self.assertEqual(s.total_packets, exp["total_packets"])
                        self.assertEqual(s.tcp_packets, exp["tcp_packets"])
                        self.assertEqual(s.udp_packets, exp["udp_packets"])
                        self.assertEqual(s.unsupported_packets, exp["unsupported"])
                        self.assertEqual(s.malformed_packets, exp["malformed"])
                        self.assertEqual(s.dropped_packets, run["rule_filtered"])
                        supported = exp["total_packets"] - exp["unsupported"] - exp["malformed"]
                        self.assertEqual(s.forwarded_packets, supported - run["rule_filtered"])
                        self.assertTrue(s.reconciles())
                        self.assertEqual(eng.flow_count, exp["flows"])

    def test_flow_classification_matches_expectations(self):
        for capture, exp in EXPECTED["captures"].items():
            want = exp.get("flows_by_app_no_rules")
            if not want:
                continue
            for make in (DPIEngine, lambda: DPIEngineMT(2, 2)):
                eng = make()
                with self.subTest(capture=capture, mode=eng.mode):
                    self._run(eng, capture)
                    got = {}
                    for c in eng.connections():
                        got[c.app_type.value] = got.get(c.app_type.value, 0) + 1
                    self.assertEqual(got, want)

    def test_rejected_captures_raise_in_process(self):
        for capture, exp in EXPECTED["rejected"].items():
            for make in (DPIEngine, lambda: DPIEngineMT(2, 2)):
                eng = make()
                with self.subTest(capture=capture, mode=eng.mode):
                    out = os.path.join(self.dir.name, "out.pcap")
                    with self.assertRaises(ProcessingError) as cm:
                        with contextlib.redirect_stdout(io.StringIO()):
                            eng.process_file(os.path.join(CAPTURES, capture), out)
                    self.assertIn(exp["stderr_contains"], str(cm.exception))
                    self.assertFalse(os.path.exists(out))
                    self.assertFalse(os.path.exists(out + ".partial"))


class TestSampleCLI(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.out = os.path.join(self.dir.name, "out.pcap")

    def tearDown(self):
        self.dir.cleanup()

    def test_rejected_captures_exit_status_and_message(self):
        for capture, exp in EXPECTED["rejected"].items():
            for mode in ("simple", "mt"):
                with self.subTest(capture=capture, mode=mode):
                    r = run_cli(os.path.join(CAPTURES, capture), self.out, "--mode", mode)
                    self.assertEqual(r.returncode, exp["exit_status"], r.stderr)
                    self.assertIn(exp["stderr_contains"], r.stderr)
                    self.assertFalse(os.path.exists(self.out))

    def test_accepted_captures_exit_zero_with_reports(self):
        for capture, exp in EXPECTED["captures"].items():
            run = exp["runs"]["none"]
            for mode in ("simple", "mt"):
                with self.subTest(capture=capture, mode=mode):
                    rj = os.path.join(self.dir.name, "r.json")
                    r = run_cli(os.path.join(CAPTURES, capture), self.out, "--mode", mode,
                                "--report-json", rj, "--report-no-timestamp", *run["args"])
                    self.assertEqual(r.returncode, 0, r.stderr)
                    with open(rj, encoding="utf-8") as f:
                        rep = json.load(f)
                    self.assertEqual(rep["accounting"]["total_packets"], exp["total_packets"])
                    self.assertEqual(rep["flows"]["total"], exp["flows"])
                    self.assertTrue(rep["accounting"]["reconciles"])


if __name__ == "__main__":
    unittest.main()
