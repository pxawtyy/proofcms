"""Inventory check for Ruby2Shell (CVE-2026-132825).

The vulnerability is a one-byte heap overflow in ``String#upcase`` (and the
related case-conversion APIs) for ISO-8859-x / Windows-125x strings. It is a
local runtime primitive, not an HTTP endpoint: this module parses ``ruby -v``
and optionally checks that the legacy-encoding case-map path is reachable.

It is an inventory helper. It does not send malformed strings or attempt the
heap-grooming/RCE chain.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from enum import Enum

CVE_ID = "CVE-2026-132825"
GHSA_ID = "GHSA-34m4-m9fh-gqp5"

_VERSION_RE = re.compile(r"ruby\s+(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)
_FALLBACK_RE = re.compile(r"\b(\d+)\.(\d+)\.(\d+)\b")
_LEGACY_PROBE = 's = ("\\xDF").force_encoding("ISO-8859-1"); print s.upcase'


class Verdict(str, Enum):
    """Outcome of the inventory check."""

    AFFECTED = "AFFECTED"
    EOL_AFFECTED = "EOL_AFFECTED"
    PATCHED = "PATCHED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class RubyInfo:
    """Parsed Ruby runtime identification."""

    raw: str
    version: str
    numbers: tuple[int, int, int]
    platform: str | None


@dataclass(frozen=True)
class CheckResult:
    """Result of one version (and optional legacy-encoding) check."""

    ruby: RubyInfo | None
    verdict: Verdict
    legacy_encoding: bool | None


def parse_ruby_version(text: str) -> RubyInfo | None:
    """Parse ``ruby -v`` output (or a raw version string)."""

    match = _VERSION_RE.search(text) or _FALLBACK_RE.search(text)
    if match is None:
        return None
    numbers = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    version = ".".join(str(part) for part in numbers)
    platform_match = re.search(r"\[([^\]]+)\]", text)
    return RubyInfo(
        raw=text.strip(),
        version=version,
        numbers=numbers,
        platform=platform_match.group(1) if platform_match else None,
    )


def classify_version(info: RubyInfo | None) -> Verdict:
    """Classify a parsed Ruby version against the fixed releases."""

    if info is None:
        return Verdict.UNKNOWN
    major, minor, patch = info.numbers
    if major < 3 or (major == 3 and minor <= 2):
        return Verdict.EOL_AFFECTED
    if major == 3 and minor == 3:
        return Verdict.PATCHED if patch >= 14 else Verdict.AFFECTED
    if major == 3 and minor == 4:
        return Verdict.PATCHED if patch >= 13 else Verdict.AFFECTED
    if major == 3:
        return Verdict.PATCHED
    if major == 4 and minor == 0:
        return Verdict.PATCHED if patch >= 10 else Verdict.AFFECTED
    if major >= 4:
        return Verdict.PATCHED
    return Verdict.UNKNOWN


def read_ruby_version(ruby: str = "ruby", timeout: int = 15) -> str | None:
    """Return the local ``ruby -v`` output, or ``None`` when unavailable."""

    try:
        result = subprocess.run(
            [ruby, "-v"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or result.stderr.strip()


def probe_legacy_encoding(ruby: str = "ruby", timeout: int = 15) -> bool | None:
    """Check that ISO-8859-1 ``upcase`` returns ``SS`` without malformed input."""

    try:
        result = subprocess.run(
            [ruby, "-e", _LEGACY_PROBE],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout == "SS"


def check(
    version_text: str | None = None,
    ruby: str = "ruby",
    probe: bool = False,
) -> CheckResult:
    """Classify a runtime, optionally probing the legacy case-map path."""

    raw = version_text if version_text is not None else read_ruby_version(ruby)
    info = parse_ruby_version(raw) if raw else None
    verdict = classify_version(info)
    legacy = probe_legacy_encoding(ruby) if probe and info is not None else None
    return CheckResult(ruby=info, verdict=verdict, legacy_encoding=legacy)


def _result_dict(result: CheckResult) -> dict[str, object]:
    return {
        "cve": CVE_ID,
        "ghsa": GHSA_ID,
        "ruby": asdict(result.ruby) if result.ruby is not None else None,
        "verdict": result.verdict.value,
        "legacy_encoding": result.legacy_encoding,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inventory check for Ruby2Shell (CVE-2026-132825).")
    parser.add_argument("--version-string", help="Raw 'ruby -v' output instead of running ruby")
    parser.add_argument("--ruby", default="ruby", help="Ruby executable (default: ruby)")
    parser.add_argument("--probe", action="store_true", help="Also check the ISO-8859-1 case-map path")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    args = parser.parse_args(argv)

    result = check(args.version_string, args.ruby, args.probe)
    if args.json:
        print(json.dumps(_result_dict(result), indent=2))
    else:
        print(f"Ruby2Shell ({CVE_ID}) inventory check")
        print(f"ruby: {result.ruby.raw if result.ruby else 'not found'}")
        print(f"verdict: {result.verdict.value}")
        if result.legacy_encoding is None:
            print("legacy_case_map: not probed")
        else:
            state = "reachable" if result.legacy_encoding else "unavailable"
            print(f"legacy_case_map: {state}")

    if result.verdict in (Verdict.AFFECTED, Verdict.EOL_AFFECTED):
        return 1
    if result.verdict is Verdict.UNKNOWN:
        return 2
    return 0
