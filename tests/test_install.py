"""
Clean-environment installation test.

Creates a fresh virtual environment, installs the project from the checkout
with ``pip install .`` and runs the ``dpi-engine`` console script and
``python -m dpi`` end to end on a sample capture.

This needs a working ``pip`` and (unless setuptools is already available to
pip's build isolation) network access to fetch the build backend.  Set
``DPI_SKIP_INSTALL_TEST=1`` to skip it locally; CI runs it.
"""

import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE = os.path.join(ROOT, "samples", "captures", "mixed_supported.pcap")


@unittest.skipIf(os.environ.get("DPI_SKIP_INSTALL_TEST") == "1", "DPI_SKIP_INSTALL_TEST=1")
class TestCleanInstall(unittest.TestCase):
    def test_pip_install_into_fresh_venv(self):
        with tempfile.TemporaryDirectory() as tmp:
            venv_dir = os.path.join(tmp, "venv")
            subprocess.run([sys.executable, "-m", "venv", venv_dir], check=True, timeout=300)
            bindir = "Scripts" if os.name == "nt" else "bin"
            py = os.path.join(venv_dir, bindir, "python" + (".exe" if os.name == "nt" else ""))
            exe = os.path.join(venv_dir, bindir, "dpi-engine" + (".exe" if os.name == "nt" else ""))

            r = subprocess.run(
                [py, "-m", "pip", "install", "--disable-pip-version-check", "--quiet", ROOT],
                capture_output=True, text=True, timeout=600,
            )
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

            # Run from a directory that is NOT the checkout so the installed package is exercised.
            r = subprocess.run([exe, "--version"], capture_output=True, text=True, cwd=tmp, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertRegex(r.stdout.strip(), r"^dpi-engine \d+\.\d+\.\d+$")

            out = os.path.join(tmp, "out.pcap")
            rep = os.path.join(tmp, "rep.json")
            r = subprocess.run(
                [exe, SAMPLE, out, "--mode", "mt", "--block-app", "YouTube", "--report-json", rep],
                capture_output=True, text=True, cwd=tmp, timeout=120, encoding="utf-8", errors="replace",
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(os.path.exists(out))
            self.assertTrue(os.path.exists(rep))

            r = subprocess.run([py, "-m", "dpi", "--help"], capture_output=True, text=True, cwd=tmp, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("--report-json", r.stdout)

            r = subprocess.run([py, "-c", "import dpi, dpi.report, dpi.engine_mt; print(dpi.__version__)"],
                               capture_output=True, text=True, cwd=tmp, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
