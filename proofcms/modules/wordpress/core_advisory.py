"""Passive WordPress core advisory helpers.

WPScan carries some core issues under WPVDB identifiers when no CVE has been
assigned.  These helpers keep those advisories in the same module contract as
CVE-backed checks without pretending that a version match is active proof.
"""

from __future__ import annotations

from typing import Any

from ...core.models import Finding
from ...core.versions import parse_version_safe


def classify_version(version: str | None, fixed_by_branch: dict[str, str]) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    branch = f"{parsed.major}.{parsed.minor}"
    fixed = parse_version_safe(fixed_by_branch.get(branch))
    if fixed is None:
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if parsed < fixed else "PATCHED"


def passive_result(
    *,
    advisory_id: str,
    name: str,
    affected_rule: str,
    fixed_by_branch: dict[str, str],
    wordpress_version: str | None,
    cvss: str,
    vulnerability_type: str,
    description: str,
    remediation: str,
    references: list[str],
    poc: str | None = None,
) -> Finding:
    status = classify_version(wordpress_version, fixed_by_branch)
    if status == "INCONCLUSIVE":
        detail = "WordPress was detected, but its core version could not be determined."
        confidence = "MEDIUM"
    elif status == "LIKELY_VULNERABLE":
        detail = f"WordPress {wordpress_version} is in the advisory's affected branch range. {description}"
        confidence = "HIGH"
    elif status == "PATCHED":
        detail = f"WordPress {wordpress_version} includes the branch-specific fix for {advisory_id}."
        confidence = "HIGH"
    else:
        detail = f"WordPress {wordpress_version} is outside the advisory's affected branches."
        confidence = "HIGH"
    if poc and status == "LIKELY_VULNERABLE":
        detail += " A documented PoC is recorded in module metadata; it is not executed automatically."
    return Finding(
        cve=advisory_id,
        name=name,
        status=status,
        confidence=confidence,
        component="WordPress core",
        component_version=wordpress_version,
        affected_rule=affected_rule,
        exploit_available=bool(poc),
        detail=detail,
        action=remediation,
        vulnerability_type=vulnerability_type,
    )


def metadata(
    *,
    advisory_id: str,
    name: str,
    affected_rule: str,
    fixed_by_branch: dict[str, str],
    cvss: str,
    vulnerability_type: str,
    references: list[str],
    poc: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "cve": advisory_id,
        "cms": "wordpress",
        "name": name,
        "component": "WordPress core",
        "affected_rule": affected_rule,
        "affected_versions": [f"{branch} < {fixed}" for branch, fixed in fixed_by_branch.items()],
        "cvss": cvss,
        "vulnerability_type": vulnerability_type,
        "exploit_available": bool(poc),
        "exploit_modes": [],
        "intrusive": False,
        "module_version": "1.0.0",
        "last_reviewed": "2026-10-11",
        "updated": "2026-10-11",
        "required_detectors": [],
        "references": references,
    }
    if poc:
        result["poc"] = poc
    return result
