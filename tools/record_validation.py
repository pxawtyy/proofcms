"""Append or replace a CVE row in the three lab documentation files.

The rows are validated by the redaction guard before writing. Use --dry-run to
inspect the exact rows first.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from proofcms.redaction import scan_text

README = REPO / "README.md"
VALIDATED = REPO / "labs" / "VALIDATED.md"
REQUIREMENTS = REPO / "labs" / "REQUIREMENTS.md"


def _table_bounds(lines: list[str], heading: str | None) -> tuple[int, int] | None:
    start = 0
    if heading:
        for index, line in enumerate(lines):
            if line.strip().lower() == f"## {heading}".lower():
                start = index
                break
        else:
            return None
    table_start = None
    for index in range(start, len(lines)):
        if lines[index].startswith("|"):
            table_start = index
            break
    if table_start is None:
        return None
    table_end = table_start
    while table_end + 1 < len(lines) and lines[table_end + 1].startswith("|"):
        table_end += 1
    return table_start, table_end


def _cve_table_bounds(lines: list[str]) -> tuple[int, int] | None:
    for index, line in enumerate(lines):
        if line.startswith("| `CVE-"):
            start = index
            while start > 0 and lines[start - 1].startswith("|"):
                start -= 1
            end = index
            while end + 1 < len(lines) and lines[end + 1].startswith("|"):
                end += 1
            return start, end
    return None


def _replace_or_append(lines: list[str], cve: str, row: str, heading: str | None) -> bool:
    prefixes = (f"| {cve} ", f"| `{cve}` ")
    for index, line in enumerate(lines):
        if line.startswith(prefixes):
            lines[index] = row
            return True
    bounds = _cve_table_bounds(lines) if heading is None else _table_bounds(lines, heading)
    if bounds is None:
        return False
    lines.insert(bounds[1] + 1, row)
    return True


def _validate(row: str, label: str) -> None:
    violations = scan_text(row, path=label)
    if violations:
        rules = ", ".join(sorted({violation.rule for violation in violations}))
        raise SystemExit(f"redaction violation in {label}: {rules}")


def _read(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def _write(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cve", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--affected", required=True)
    parser.add_argument("--mode", default="passive")
    parser.add_argument("--section", help="VALIDATED.md section heading")
    parser.add_argument("--fixture", default="-")
    parser.add_argument("--probe", default="-")
    parser.add_argument("--disposition", default="NOT_YET_VALIDATED")
    parser.add_argument("--patched", default="-")
    parser.add_argument("--lab", default="-")
    parser.add_argument("--date", default=datetime.now(timezone.utc).date().isoformat())
    parser.add_argument("--requirements-section", default="PHP runtime labs")
    parser.add_argument("--notes", default="-")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--skip-readme", action="store_true")
    parser.add_argument("--skip-validated", action="store_true")
    parser.add_argument("--skip-requirements", action="store_true")
    args = parser.parse_args()

    mode = args.mode if args.mode == "passive" else f"`{args.mode}`"
    lab = args.lab if args.lab == "-" else f"`{args.lab}`"
    readme_row = f"| `{args.cve}` | {args.name} | {args.affected} | {mode} |"
    validated_row = (
        f"| {args.cve} | {args.fixture} | {args.probe} | {args.disposition} | "
        f"{args.patched} | {lab} | {args.date} |"
    )
    requirements_row = f"| {args.cve} | {args.affected} | {args.fixture} | {args.notes} |"

    changes: list[tuple[Path, list[str]]] = []
    if not args.skip_readme:
        _validate(readme_row, "README.md")
        lines = _read(README)
        if not _replace_or_append(lines, args.cve, readme_row, None):
            raise SystemExit("README.md: no CVE table found")
        changes.append((README, lines))
    if not args.skip_validated:
        _validate(validated_row, "labs/VALIDATED.md")
        lines = _read(VALIDATED)
        if not _replace_or_append(lines, args.cve, validated_row, args.section):
            raise SystemExit("labs/VALIDATED.md: section/table not found")
        changes.append((VALIDATED, lines))
    if not args.skip_requirements:
        _validate(requirements_row, "labs/REQUIREMENTS.md")
        lines = _read(REQUIREMENTS)
        if not _replace_or_append(lines, args.cve, requirements_row, args.requirements_section):
            raise SystemExit("labs/REQUIREMENTS.md: section/table not found")
        changes.append((REQUIREMENTS, lines))

    for path, lines in changes:
        if args.dry_run:
            print(f"--- {path.relative_to(REPO)}")
            prefixes = (f"| {args.cve} ", f"| `{args.cve}` ")
            print("\n".join(line for line in lines if line.startswith(prefixes)))
        else:
            _write(path, lines)
            print(f"updated {path.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
