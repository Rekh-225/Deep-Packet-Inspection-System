"""Allow ``python -m dpi input.pcap output.pcap [options]``."""

import sys

from dpi.cli import main

if __name__ == "__main__":
    sys.exit(main())
