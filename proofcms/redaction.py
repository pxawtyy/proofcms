"""Repository redaction guard.

Target data is ephemeral: hostnames, codenames, report slugs, and vendor
build IDs must never enter the public repository. This checker scans tracked
(or staged) text files and reports only the file, line, and rule name — never
the matched value — so CI logs cannot re-expose it.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_SKIP_PREFIXES = ("reports/", "logs/", ".git/")
_SKIP_SUFFIXES = {
    ".bundle",
    ".gif",
    ".gz",
    ".ico",
    ".jpeg",
    ".jpg",
    ".pdf",
    ".png",
    ".pyc",
    ".tgz",
    ".zip",
}
_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("gov-br-host", re.compile(r"\b[a-z0-9][a-z0-9.-]*\.gov\.br\b", re.IGNORECASE)),
    ("edu-br-host", re.compile(r"\b[a-z0-9][a-z0-9.-]*\.edu\.br\b", re.IGNORECASE)),
    # Codenames are split so this file does not match its own rules.
    ("target-codename", re.compile(r"\b(?:" + "si" "ga|fa" "tec|pro" "desp|cp" r"s)\b", re.IGNORECASE)),
    ("target-report-slug", re.compile(r"\b[a-z0-9][a-z0-9-]*-gov-br\b", re.IGNORECASE)),
    ("vendor-build", re.compile(r"\b10_1_8-\d{5}\b")),
)


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    rule: str


def scan_text(text: str, path: str = "<text>") -> list[Violation]:
    violations: list[Violation] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule, pattern in _RULES:
            if pattern.search(line):
                violations.append(Violation(path=path, line=line_number, rule=rule))
    return violations


def _is_text_path(path: str) -> bool:
    if path.startswith(_SKIP_PREFIXES):
        return False
    return Path(path).suffix.lower() not in _SKIP_SUFFIXES


def _tracked_files() -> Iterator[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
    )
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        path = raw.decode("utf-8", "replace")
        if _is_text_path(path) and (REPO_ROOT / path).is_file():
            yield path


def scan_all() -> list[Violation]:
    violations: list[Violation] = []
    for path in _tracked_files():
        text = (REPO_ROOT / path).read_text(encoding="utf-8", errors="replace")
        violations.extend(scan_text(text, path=path))
    return violations


def scan_staged() -> list[Violation]:
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
    )
    violations: list[Violation] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        path = raw.decode("utf-8", "replace")
        if not _is_text_path(path):
            continue
        blob = subprocess.run(
            ["git", "show", f":{path}"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
        ).stdout
        violations.extend(scan_text(blob.decode("utf-8", "replace"), path=path))
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Block target-identifying data in tracked files.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--all", action="store_true", help="scan every tracked text file (default)")
    mode.add_argument("--staged", action="store_true", help="scan staged content for the pre-commit hook")
    args = parser.parse_args(argv)
    violations = scan_staged() if args.staged else scan_all()
    for violation in violations:
        print(f"{violation.path}:{violation.line}: {violation.rule}")
    if violations:
        print(f"{len(violations)} redaction violation(s); use target.example/fixture.test placeholders.", file=sys.stderr)
        return 1
    print("redaction check: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
