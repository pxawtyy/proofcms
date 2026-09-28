from __future__ import annotations

import json
from pathlib import Path


def write_json_report(path: Path | str, report: dict):
    """Writes the full scan report as formatted JSON."""
    report_path = Path(path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
