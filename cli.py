#!/usr/bin/env python3
"""
Compatibility launcher: ``python cli.py <input.pcap> <output.pcap> [options]``.

The CLI itself lives in ``dpi/cli.py`` and is installed as the ``dpi-engine``
console script (``pip install .``); ``python -m dpi`` also works.  This file
keeps the original invocation working from a repository checkout.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dpi.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
