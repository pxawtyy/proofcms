"""Shared passive policy for the October 2026 PHP memory-safety advisories."""

from __future__ import annotations

from typing import Any

from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_required, parse_version_safe

FIXED_BY_BRANCH = {
    "8.2": "8.2.35",
    "8.3": "8.3.36",
    "8.4": "8.4.27",
    "8.5": "8.5.12",
}
LEGACY_BRANCHES = {"7.4", "8.0", "8.1"}


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return Status.DETECTED_VERSION_UNKNOWN
    branch = f"{parsed.major}.{parsed.minor}"
    fixed = FIXED_BY_BRANCH.get(branch)
    if fixed:
        return Status.LIKELY_VULNERABLE if parsed < parse_version_required(fixed) else Status.PATCHED
    if branch in LEGACY_BRANCHES:
        # These branches have no upstream fixed release. A public version
        # string cannot distinguish an old build from a vendor backport.
        return Status.NOT_CONFIRMED
    return Status.NOT_AFFECTED


def runtime_finding(
    *,
    cve: str,
    name: str,
    vulnerability_type: str,
    rule: str,
    action: str,
    php_runtime: dict[str, Any] | None,
) -> Finding:
    runtime = php_runtime or {}
    version = runtime.get("version")
    if not runtime.get("detected"):
        return Finding(
            cve,
            name,
            Status.NOT_DETECTED,
            Confidence.LOW,
            "PHP runtime",
            affected_rule=rule,
            detail="PHP was not fingerprinted from public HTTP responses.",
            action=action,
            vulnerability_type=vulnerability_type,
        )

    status = classify_version(version)
    if status == Status.LIKELY_VULNERABLE:
        detail = (
            f"Detected PHP {version}; the public version is within the advisory's affected range. "
            "This is a passive version result, not proof of a crash or code execution."
        )
        confidence = Confidence.MEDIUM
    elif status == Status.PATCHED:
        detail = f"Detected PHP {version}, which is at or beyond the branch-specific fixed release."
        confidence = Confidence.HIGH
    elif status == Status.NOT_CONFIRMED:
        detail = (
            f"Detected PHP {version} on an EOL branch without an upstream fixed release. "
            "The effective status depends on the distributor package and any backported patch; php -v alone is insufficient."
        )
        confidence = Confidence.MEDIUM
    else:
        detail = "PHP was detected, but its version could not be placed in the published affected ranges."
        confidence = Confidence.LOW
    return Finding(
        cve,
        name,
        status,
        confidence,
        "PHP runtime",
        version,
        rule,
        detail=detail,
        action=action,
        evidence={
            "source": runtime.get("source"),
            "server": runtime.get("server"),
            "active_probe": "not_sent",
            "package_backport_required": status == Status.NOT_CONFIRMED,
        },
        vulnerability_type=vulnerability_type,
    )


def metadata(*, cve: str, name: str, vulnerability_type: str, rule: str, references: list[str]) -> dict[str, Any]:
    return {
        "cve": cve,
        "cms": "php",
        "name": name,
        "component": "PHP runtime",
        "affected_rule": rule,
        "affected_versions": ["7.4.x/8.0.x/8.1.x: package-specific", ">=8.2.0,<8.2.35", ">=8.3.0,<8.3.36", ">=8.4.0,<8.4.27", ">=8.5.0,<8.5.12"],
        "exploit_available": False,
        "exploit_modes": [],
        "intrusive": True,
        "vulnerability_type": vulnerability_type,
        "references": references,
    }
