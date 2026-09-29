#!/usr/bin/env python3
"""
Assemble a LOCAL release archive under ./release/.  Nothing is uploaded.

    python tools/make_release.py [--no-build-isolation] [--skip-tests]

Steps
  1. run the test suite (unless --skip-tests)
  2. build the wheel with ``pip wheel`` (SOURCE_DATE_EPOCH pinned for reproducibility)
  3. snapshot the source tree into a deterministic zip
  4. copy docs, samples (captures, rules, expected results, reports), demo and benchmark notes
  5. write SHA256SUMS, zip the release directory, print the archive checksum

Zips use fixed timestamps and sorted entries so repeated runs on the same tree
produce identical bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from dpi import __version__  # noqa: E402

NAME = f"dpi-engine-{__version__}"
RELEASE_ROOT = os.path.join(ROOT, "release")
STAGE = os.path.join(RELEASE_ROOT, NAME)
FIXED_TIME = (1980, 1, 1, 0, 0, 0)
SOURCE_DATE_EPOCH = "315532800"   # 1980-01-01T00:00:00Z

SOURCE_INCLUDE = [
    "dpi", "tests", "samples", "docs", "benchmarks", "tools", ".github",
    "cli.py", "demo.py", "generate_test_pcap.py", "pyproject.toml", "README.md", "LICENSE",
    "requirements.txt", "test_dpi.pcap", ".gitignore",
]
SOURCE_EXCLUDE_DIRS = {"__pycache__"}
SOURCE_EXCLUDE_FILES = {"last_run.json"}


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def add_to_zip(zf: zipfile.ZipFile, src: str, arcname: str) -> None:
    info = zipfile.ZipInfo(arcname.replace(os.sep, "/"), date_time=FIXED_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    with open(src, "rb") as f:
        zf.writestr(info, f.read())


def iter_tree(base: str, rel_prefix: str):
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if d not in SOURCE_EXCLUDE_DIRS)
        for fn in sorted(filenames):
            if fn in SOURCE_EXCLUDE_FILES or fn.endswith((".pyc", ".pyo")):
                continue
            full = os.path.join(dirpath, fn)
            yield full, os.path.join(rel_prefix, os.path.relpath(full, base))


def build_source_zip(dest: str) -> None:
    with zipfile.ZipFile(dest, "w") as zf:
        for item in SOURCE_INCLUDE:
            src = os.path.join(ROOT, item)
            if os.path.isdir(src):
                for full, rel in iter_tree(src, os.path.join(NAME, item)):
                    add_to_zip(zf, full, rel)
            elif os.path.isfile(src):
                add_to_zip(zf, src, os.path.join(NAME, item))


def run(cmd, **kw) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, check=True, cwd=ROOT, **kw)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--no-build-isolation", action="store_true",
                    help="use the already-installed setuptools instead of downloading a build backend")
    ap.add_argument("--skip-tests", action="store_true")
    args = ap.parse_args()

    if not args.skip_tests:
        env = dict(os.environ, DPI_SKIP_INSTALL_TEST="1", PYTHONUTF8="1")
        run([sys.executable, "-m", "unittest", "discover", "-s", "tests"], env=env)
        run([sys.executable, os.path.join("samples", "make_samples.py"), "--check"])

    if os.path.isdir(STAGE):
        shutil.rmtree(STAGE)
    os.makedirs(STAGE)

    # 1. wheel
    wheel_cmd = [sys.executable, "-m", "pip", "wheel", "--no-deps", "--disable-pip-version-check",
                 "-w", STAGE, ROOT]
    if args.no_build_isolation:
        wheel_cmd.insert(-2, "--no-build-isolation")
    run(wheel_cmd, env=dict(os.environ, SOURCE_DATE_EPOCH=SOURCE_DATE_EPOCH))
    for junk in ("build", "dpi_engine.egg-info"):
        shutil.rmtree(os.path.join(ROOT, junk), ignore_errors=True)

    # 2. source snapshot
    build_source_zip(os.path.join(STAGE, f"{NAME}-source.zip"))

    # 3. docs, samples, demo, benchmark notes
    shutil.copy(os.path.join(ROOT, "README.md"), STAGE)
    shutil.copy(os.path.join(ROOT, "LICENSE"), STAGE)
    shutil.copy(os.path.join(ROOT, "docs", "USAGE.md"), STAGE)
    shutil.copy(os.path.join(ROOT, "docs", "REVIEW_REPAIRS.md"), STAGE)
    shutil.copy(os.path.join(ROOT, "demo.py"), STAGE)
    shutil.copy(os.path.join(ROOT, "cli.py"), STAGE)
    shutil.copytree(os.path.join(ROOT, "samples"), os.path.join(STAGE, "samples"),
                    ignore=shutil.ignore_patterns("__pycache__", ".tmp.pcap"))
    os.makedirs(os.path.join(STAGE, "benchmarks"))
    shutil.copy(os.path.join(ROOT, "benchmarks", "README.md"), os.path.join(STAGE, "benchmarks"))
    shutil.copy(os.path.join(ROOT, "benchmarks", "bench.py"), os.path.join(STAGE, "benchmarks"))
    if os.path.exists(os.path.join(ROOT, "benchmarks", "last_run.json")):
        shutil.copy(os.path.join(ROOT, "benchmarks", "last_run.json"), os.path.join(STAGE, "benchmarks"))
    # demo.py / bench.py import tests.fixtures; ship that builder so the archive is self-contained
    os.makedirs(os.path.join(STAGE, "tests"))
    shutil.copy(os.path.join(ROOT, "tests", "__init__.py"), os.path.join(STAGE, "tests"))
    shutil.copy(os.path.join(ROOT, "tests", "fixtures.py"), os.path.join(STAGE, "tests"))

    # 4. checksums
    entries = []
    for full, rel in iter_tree(STAGE, ""):
        entries.append((rel.replace(os.sep, "/").lstrip("/"), sha256(full)))
    with open(os.path.join(STAGE, "SHA256SUMS"), "w", encoding="utf-8", newline="\n") as f:
        for rel, digest in entries:
            f.write(f"{digest}  {rel}\n")

    # 5. archive
    archive = os.path.join(RELEASE_ROOT, f"{NAME}.zip")
    if os.path.exists(archive):
        os.unlink(archive)
    with zipfile.ZipFile(archive, "w") as zf:
        for full, rel in iter_tree(STAGE, NAME):   # includes SHA256SUMS written above
            add_to_zip(zf, full, rel)

    print()
    print(f"release directory: {STAGE}")
    print(f"release archive:   {archive}")
    print(f"  size   {os.path.getsize(archive)} bytes")
    print(f"  sha256 {sha256(archive)}")
    for fn in sorted(os.listdir(STAGE)):
        p = os.path.join(STAGE, fn)
        if os.path.isfile(p) and fn != "SHA256SUMS":
            print(f"  {sha256(p)}  {fn}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
