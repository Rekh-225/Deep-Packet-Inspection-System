"""
End-to-end CLI tests: exit status must reflect whether a complete output was produced.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

from tests import fixtures as fx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, "cli.py")


def run_cli(*args):
    return subprocess.run(
        [sys.executable, CLI, *args], cwd=ROOT, capture_output=True, timeout=120,
        encoding="utf-8", errors="replace",
    )


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.inp = os.path.join(self.dir.name, "in.pcap")
        self.out = os.path.join(self.dir.name, "out.pcap")
        self.fixture = fx.mixed_with_unsupported_fixture()
        fx.write_pcap(self.inp, self.fixture.packets)

    def tearDown(self):
        self.dir.cleanup()

    def test_success_both_modes(self):
        for mode in ("simple", "mt"):
            with self.subTest(mode=mode):
                r = run_cli(self.inp, self.out, "--mode", mode, "--block-ip", fx.BLOCKED_CLIENT)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(len(fx.read_pcap(self.out)), self.fixture.supported - 5)
                self.assertFalse(os.path.exists(self.out + ".partial"))
                self.assertIn("Unsupported:", r.stdout)
                self.assertIn("Malformed:", r.stdout)

    def test_missing_input_is_nonzero(self):
        for mode in ("simple", "mt"):
            r = run_cli(os.path.join(self.dir.name, "missing.pcap"), self.out, "--mode", mode)
            self.assertEqual(r.returncode, 1, mode)
            self.assertIn("Error", r.stderr)
            self.assertFalse(os.path.exists(self.out))

    def test_unwritable_output_is_nonzero(self):
        bad = os.path.join(self.dir.name, "no", "such", "dir", "out.pcap")
        r = run_cli(self.inp, bad, "--mode", "mt")
        self.assertEqual(r.returncode, 1)

    def test_bad_rules_file_is_nonzero(self):
        r = run_cli(self.inp, self.out, "--rules-file", os.path.join(self.dir.name, "none.rules"))
        self.assertEqual(r.returncode, 2)

    def test_invalid_thread_counts_are_usage_errors(self):
        r = run_cli(self.inp, self.out, "--mode", "mt", "--lbs", "0")
        self.assertEqual(r.returncode, 2)

    def test_version_and_module_invocation(self):
        r = run_cli("--version")
        self.assertEqual(r.returncode, 0)
        self.assertRegex(r.stdout.strip(), r"^dpi-engine \d+\.\d+\.\d+$")
        r = subprocess.run([sys.executable, "-m", "dpi", "--version"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("dpi-engine", r.stdout)

    def test_reports_written_only_on_success(self):
        rj = os.path.join(self.dir.name, "r.json")
        rh = os.path.join(self.dir.name, "r.html")
        r = run_cli(self.inp, self.out, "--mode", "mt", "--block-ip", fx.BLOCKED_CLIENT,
                    "--report-json", rj, "--report-html", rh, "--report-max-flows", "3")
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(rj, encoding="utf-8") as f:
            rep = json.load(f)
        self.assertEqual(rep["accounting"]["rule_filtered"], 5)
        self.assertEqual(rep["flows"]["listed"], 3)
        self.assertTrue(rep["flows"]["truncated"])
        self.assertIsNotNone(rep["generated_at"])
        with open(rh, encoding="utf-8") as f:
            self.assertIn("<!DOCTYPE html>", f.read())

        # A failing run must not produce a report.
        rj2 = os.path.join(self.dir.name, "never.json")
        r = run_cli(os.path.join(self.dir.name, "missing.pcap"), self.out, "--report-json", rj2)
        self.assertEqual(r.returncode, 1)
        self.assertFalse(os.path.exists(rj2))

    def test_unwritable_report_path_is_exit_3_with_capture_kept(self):
        bad = os.path.join(self.dir.name, "no", "dir", "r.json")
        r = run_cli(self.inp, self.out, "--report-json", bad)
        self.assertEqual(r.returncode, 3)
        self.assertIn("capture completed; report failed", r.stderr)
        self.assertTrue(os.path.exists(self.out), "capture must be preserved")
        self.assertFalse(os.path.exists(bad))

    def test_negative_report_max_flows_is_usage_error(self):
        r = run_cli(self.inp, self.out, "--report-max-flows", "-1")
        self.assertEqual(r.returncode, 2)

    def test_rules_file_works_in_mt_mode(self):
        rules = os.path.join(self.dir.name, "r.rules")
        with open(rules, "w") as f:
            f.write("[BLOCKED_IPS]\n" + fx.BLOCKED_CLIENT + "\n")
        r = run_cli(self.inp, self.out, "--mode", "mt", "--rules-file", rules)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(fx.read_pcap(self.out)), self.fixture.supported - 5)


if __name__ == "__main__":
    unittest.main()
