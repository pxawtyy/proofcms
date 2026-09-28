from __future__ import annotations

import json
from typing import Any

from ...core.http import normalize_url, request
from ...core.models import Finding
from ...core.versions import parse_version_safe
from . import cve_2026_60137

CVE_ID = "CVE-2026-63030"
NAME = "WordPress core REST API batch-route confusion"
COMPONENT = "WordPress core"
AFFECTED_RULE = "WordPress 6.9.0-6.9.4 and 7.0.0-7.0.1"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]

FIRST_FIXED_BY_BRANCH = {
    "6.9": "6.9.5",
    "7.0": "7.0.2",
}


def classify_version(wordpress_version: str | None) -> str:
    version = parse_version_safe(wordpress_version)
    if version is None:
        return "INCONCLUSIVE"
    branch = f"{version.major}.{version.minor}"
    fixed = parse_version_safe(FIRST_FIXED_BY_BRANCH.get(branch))
    if fixed is None:
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if version < fixed else "PATCHED"


def passive_result(wordpress_version: str | None) -> Finding:
    status = classify_version(wordpress_version)
    if status == "INCONCLUSIVE":
        detail = "WordPress was detected, but its core version could not be determined."
        action = "Determine the core version and upgrade affected branches to their fixed security release."
        confidence = "MEDIUM"
    elif status == "LIKELY_VULNERABLE":
        detail = f"WordPress {wordpress_version} is within an affected range published by WordPress."
        action = "Upgrade to WordPress 6.9.5, 7.0.2, or a newer supported release as appropriate."
        confidence = "HIGH"
    elif status == "PATCHED":
        detail = f"WordPress {wordpress_version} includes the branch-specific fix for CVE-2026-63030."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = f"WordPress {wordpress_version} is outside the advisory's affected branches."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence=confidence,
        component=COMPONENT,
        component_version=wordpress_version,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=detail,
        action=action,
    )


def batch_route_available(target_url: str, timeout: int = 12, proxy: str | None = None) -> bool:
    response = request(
        f"{normalize_url(target_url)}/?rest_route=/batch/v1",
        method="POST",
        headers={"Content-Type": "application/json"},
        data=json.dumps({}),
        timeout=timeout,
        proxy=proxy,
    )
    body = response.get("body", "")
    return response.get("status", 0) > 0 and (
        "rest_missing_callback_param" in body or "rest_invalid_param" in body
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    if not batch_route_available(target_url, timeout=timeout, proxy=proxy):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail="The public REST batch endpoint was not confirmed, so the stock delivery path could not be tested.",
            action="Upgrade any version in the published affected ranges even when active proof is inconclusive.",
        )

    combined = cve_2026_60137.run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    if combined.status == "VULNERABLE":
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=combined.proof_url,
            detail=(
                "The nested REST batch request reached the SQL timing sink, confirming the route-confusion "
                "delivery path used by wp2shell. No data was extracted and no RCE payload was sent. "
                + combined.detail
            ),
            action="Upgrade WordPress to the fixed release for the installed branch immediately.",
        )
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="NOT_CONFIRMED",
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=True,
        detail="The REST batch endpoint exists, but the safe combined-path proof was inconclusive. " + combined.detail,
        action="Upgrade any version in the published affected ranges even when active proof is inconclusive.",
    )


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aggressive_command: str | None = None,
    plugins: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Finding:
    passive = passive_result(cms_version)
    if not run_exploit_check:
        return passive
    if exploit_mode != "safe":
        passive.detail += " This module supports only the safe combined-path proof."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        passive.detail += " Safe proof skipped because the detected version is outside the affected range."
        return passive
    result = run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    result.component_version = cms_version
    return result


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "wordpress",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_versions": ["6.9.0-6.9.4", "7.0.0-7.0.1"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "module_version": "1.0.0",
        "last_reviewed": "2026-09-28",
        "updated": "2026-09-28",
        "required_detectors": [],
        "references": [
            "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q",
            "https://wordpress.org/news/2026/07/wordpress-7-0-2-release/",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-63030",
            "https://github.com/ZephrFish/wp2shell-scanner",
        ],
    }
