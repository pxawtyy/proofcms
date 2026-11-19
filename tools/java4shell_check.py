"""CLI wrapper for the Java4Shell inventory check."""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from proofcms.java4shell import main

if __name__ == "__main__":
    raise SystemExit(main())
