"""Allow ``python -m gpo_lens``."""

from __future__ import annotations

import sys

from gpo_lens.cli import main

if __name__ == "__main__":
    sys.exit(main())
