"""Inventory check for Java4Shell (CVE-2026-114938).

The vulnerability is only reachable on x86-64 CPUs with AVX-512 VBMI and on
affected OpenJDK branches. This module parses ``java -version`` output and the
CPU flags, then reports whether the local runtime matches both conditions.

It is an inventory helper, not a remote probe: no malformed input is sent and
no memory corruption is triggered.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path

REQUIRED_FLAGS = frozenset({"avx512f", "avx512bw", "avx512vbmi", "bmi2"})

_VERSION_RE = re.compile(r'version\s+"([^"]+)"', re.IGNORECASE)
_FALLBACK_RE = re.compile(r"\b(\d+(?:\.\d+)+(?:[._+-][0-9A-Za-z]+)*)\b")
_JAVA8_RE = re.compile(r"\b8u(\d+)(?:b(\d+))?\b", re.IGNORECASE)


class Verdict(str, Enum):
    """Outcome of the inventory check."""

    AFFECTED = "AFFECTED"
    PATCHED = "PATCHED"
    NOT_AFFECTED_VERSION = "NOT_AFFECTED_VERSION"
    NOT_AFFECTED_HARDWARE = "NOT_AFFECTED_HARDWARE"
    MITIGATED = "MITIGATED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class JavaInfo:
    """Parsed Java runtime identification."""

    raw: str
    version: str
    vendor: str
    numbers: tuple[int, ...]


@dataclass(frozen=True)
class CheckResult:
    """Result of comparing one runtime and one CPU flag set."""

    java: JavaInfo | None
    version_verdict: Verdict
    cpu_flags: frozenset[str] | None
    missing_flags: tuple[str, ...]
    mitigation: str | None
    verdict: Verdict


def _version_numbers(version: str) -> tuple[int, ...]:
    value = version.split("+", 1)[0].split("-", 1)[0]

    java8 = _JAVA8_RE.search(value)
    if java8:
        update_number = int(java8.group(1))
        build_number = int(java8.group(2) or 0)
        return (8, 0, update_number, build_number)

    if value.startswith("1."):
        parts = value.split(".")
        if len(parts) >= 3:
            update_text = parts[2]
            if "_" in update_text:
                update_text = update_text.split("_", 1)[1]
            return (int(parts[1]), int(parts[2].split("_", 1)[0]), int(update_text))

    numbers: list[int] = []
    for part in re.split(r"[._]", value):
        match = re.match(r"\d+", part)
        if match:
            numbers.append(int(match.group(0)))
    return tuple(numbers)


def parse_java_version(text: str) -> JavaInfo | None:
    """Parse ``java -version`` output (or a raw version string)."""

    match = _VERSION_RE.search(text)
    if match is None:
        match = _FALLBACK_RE.search(text)
    if match is None:
        return None

    version = match.group(1)
    numbers = _version_numbers(version)
    if not numbers:
        return None

    lower = text.lower()
    if any(name in lower for name in ("openjdk", "temurin", "corretto", "zulu", "liberica", "sapmachine")):
        vendor = "openjdk"
    elif "oracle" in lower or "java(tm)" in lower:
        vendor = "oracle"
    else:
        vendor = "unknown"

    return JavaInfo(raw=text.strip(), version=version, vendor=vendor, numbers=numbers)


def _pad(value: tuple[int, ...], width: int) -> tuple[int, ...]:
    return value + (0,) * (width - len(value))


def _lt(left: tuple[int, ...], right: tuple[int, ...]) -> bool:
    width = max(len(left), len(right))
    return _pad(left, width) < _pad(right, width)


def classify_version(info: JavaInfo) -> Verdict:
    """Map a parsed version to the affected/fixed matrix."""

    numbers = info.numbers
    if not numbers:
        return Verdict.UNKNOWN

    major = numbers[0]

    if major == 17:
        if _lt(numbers, (17, 0, 6)):
            return Verdict.NOT_AFFECTED_VERSION
        if _lt(numbers, (17, 0, 21, 1)):
            return Verdict.AFFECTED
        return Verdict.PATCHED

    if major == 21:
        if _lt(numbers, (21, 0, 13, 1)):
            return Verdict.AFFECTED
        return Verdict.PATCHED

    if major == 25:
        if _lt(numbers, (25, 0, 5, 1)):
            return Verdict.AFFECTED
        return Verdict.PATCHED

    if major == 27:
        if _lt(numbers, (27, 0, 1, 1)):
            return Verdict.AFFECTED
        return Verdict.PATCHED

    if major == 8:
        update = numbers[2] if len(numbers) > 2 else 0
        raw = info.raw.lower()
        if update == 511 and ("b33" in raw or "perf" in raw):
            return Verdict.AFFECTED
        if update >= 513:
            return Verdict.PATCHED
        return Verdict.UNKNOWN

    if major == 11:
        if _lt(numbers, (11, 0, 33, 1)):
            return Verdict.UNKNOWN
        return Verdict.PATCHED

    return Verdict.NOT_AFFECTED_VERSION


def parse_cpu_flags(text: str) -> frozenset[str]:
    """Return the CPU flag set from ``/proc/cpuinfo`` text."""

    for line in text.splitlines():
        if line.lower().startswith("flags"):
            _, _, rest = line.partition(":")
            return frozenset(rest.split())
    return frozenset()


def mitigation_from_env(env: Mapping[str, str]) -> str | None:
    """Return the mitigation option found in the JVM option environment."""

    for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"):
        value = env.get(key, "")
        if "-XX:-UseBASE64Intrinsics" in value or "-XX:UseAVX=2" in value:
            return f"{key}={value}"
    return None


def check(
    java_text: str,
    cpu_flags: frozenset[str] | None,
    env: Mapping[str, str] | None = None,
) -> CheckResult:
    """Check one runtime against the version and hardware conditions."""

    info = parse_java_version(java_text)
    mitigation = mitigation_from_env(env or {})

    if info is None:
        return CheckResult(
            java=None,
            version_verdict=Verdict.UNKNOWN,
            cpu_flags=cpu_flags,
            missing_flags=(),
            mitigation=mitigation,
            verdict=Verdict.UNKNOWN,
        )

    version_verdict = classify_version(info)
    missing = tuple(sorted(REQUIRED_FLAGS - cpu_flags)) if cpu_flags is not None else ()

    verdict: Verdict
    if version_verdict != Verdict.AFFECTED:
        verdict = version_verdict
    elif cpu_flags is None:
        verdict = Verdict.UNKNOWN
    elif missing:
        verdict = Verdict.NOT_AFFECTED_HARDWARE
    elif mitigation:
        verdict = Verdict.MITIGATED
    else:
        verdict = Verdict.AFFECTED

    return CheckResult(
        java=info,
        version_verdict=version_verdict,
        cpu_flags=cpu_flags,
        missing_flags=missing,
        mitigation=mitigation,
        verdict=verdict,
    )


def read_java_version(java: str = "java") -> str:
    """Run ``java -version`` and return stdout+stderr."""

    try:
        completed = subprocess.run(
            [java, "-version"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return (completed.stdout or "") + (completed.stderr or "")


def read_cpu_flags(path: Path) -> frozenset[str] | None:
    """Read CPU flags from a cpuinfo file, or ``None`` when unavailable."""

    try:
        return parse_cpu_flags(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return None


def format_report(result: CheckResult, cpu_source: str) -> str:
    """Render a human-readable report."""

    lines = ["Java4Shell (CVE-2026-114938) inventory check"]

    if result.java is None:
        lines.append("java: could not parse the version output")
    else:
        info = result.java
        lines.append(f"java: {info.vendor} {info.version} (major {info.numbers[0]})")
        lines.append(f"version status: {result.version_verdict.value}")

    if result.cpu_flags is None:
        lines.append(f"cpu: {cpu_source} (flags unavailable)")
        lines.append("hardware status: UNKNOWN")
    else:
        missing = ", ".join(result.missing_flags) or "none"
        lines.append(f"cpu: {cpu_source}")
        lines.append(f"required flags missing: {missing}")
        if result.missing_flags:
            lines.append("hardware status: NOT_AFFECTED_HARDWARE")
        else:
            lines.append("hardware status: AFFECTED_HARDWARE")

    lines.append(f"mitigation: {result.mitigation or 'none'}")
    lines.append(f"verdict: {result.verdict.value}")
    return "\n".join(lines)


def _json_payload(result: CheckResult, cpu_source: str) -> dict[str, object]:
    return {
        "java": asdict(result.java) if result.java is not None else None,
        "version_verdict": result.version_verdict.value,
        "cpu_source": cpu_source,
        "cpu_flags": sorted(result.cpu_flags) if result.cpu_flags is not None else None,
        "missing_flags": list(result.missing_flags),
        "mitigation": result.mitigation,
        "verdict": result.verdict.value,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Inventory check for Java4Shell (CVE-2026-114938).",
    )
    parser.add_argument("--java", default="java", help="java executable (default: java)")
    parser.add_argument(
        "--version-string",
        help="parse this text instead of running the java executable",
    )
    parser.add_argument(
        "--cpu-flags",
        help="space-separated CPU flags (overrides /proc/cpuinfo)",
    )
    parser.add_argument(
        "--cpuinfo",
        default="/proc/cpuinfo",
        help="cpuinfo path (default: /proc/cpuinfo)",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    java_text = args.version_string if args.version_string else read_java_version(args.java)

    if args.cpu_flags is not None:
        cpu_flags: frozenset[str] | None = frozenset(args.cpu_flags.split())
        cpu_source = "argument"
    else:
        cpu_flags = read_cpu_flags(Path(args.cpuinfo))
        cpu_source = args.cpuinfo if cpu_flags is not None else "unavailable"

    result = check(java_text, cpu_flags)

    if args.json:
        print(json.dumps(_json_payload(result, cpu_source), indent=2, sort_keys=True))
    else:
        print(format_report(result, cpu_source))

    if result.verdict == Verdict.AFFECTED:
        return 1
    if result.verdict == Verdict.UNKNOWN:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
