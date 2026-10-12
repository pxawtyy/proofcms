from __future__ import annotations

import re
import secrets
import urllib.parse
from typing import Any

from ...core.http import normalize_url, request
from ...core.models import Finding
from .core_advisory import classify_version as _classify
from .core_advisory import metadata as advisory_metadata
from .core_advisory import passive_result

CVE_ID = "CVE-2026-64638"
NAME = "WordPress core pre-auth reflected XSS on login screen"
COMPONENT = "WordPress core"
AFFECTED_RULE = "WordPress 4.7.0 through branch-specific releases fixed in 4.7.34-7.0.3"
FIXED_BY_BRANCH = {"4.7": "4.7.34", "4.8": "4.8.29", "4.9": "4.9.30", "5.0": "5.0.26", "5.1": "5.1.23", "5.2": "5.2.25", "5.3": "5.3.22", "5.4": "5.4.20", "5.5": "5.5.19", "5.6": "5.6.18", "5.7": "5.7.16", "5.8": "5.8.14", "5.9": "5.9.14", "6.0": "6.0.13", "6.1": "6.1.11", "6.2": "6.2.10", "6.3": "6.3.9", "6.4": "6.4.9", "6.5": "6.5.9", "6.6": "6.6.6", "6.7": "6.7.6", "6.8": "6.8.7", "6.9": "6.9.6", "7.0": "7.0.3"}
EXPLOIT_MODES = ["safe"]


def classify_version(version: str | None) -> str:
    return _classify(version, FIXED_BY_BRANCH)


def _finding(status: str, confidence: str, version: str | None, detail: str, evidence: dict[str, Any]) -> Finding:
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence=confidence,
        component=COMPONENT,
        component_version=version,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        detail=detail,
        action="Upgrade WordPress to the fixed release for the installed branch or a newer supported branch.",
        evidence=evidence,
        vulnerability_type="Cross-Site Scripting (XSS)",
    )


def run_safe_probe(
    target_url: str,
    wordpress_version: str | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Check the disclosed parser differential with an inert reflected HTML marker."""
    login_url = f"{normalize_url(target_url).rstrip('/')}/wp-login.php"
    baseline = request(login_url, timeout=timeout, proxy=proxy)
    if baseline.get("status") in {401, 403}:
        return _finding(
            "BLOCKED_EXTERNAL",
            "MEDIUM",
            wordpress_version,
            f"The login endpoint rejected the baseline request with HTTP {baseline.get('status')}; reflection cannot be tested externally.",
            {"baseline_status": baseline.get("status"), "proof_sent": False},
        )
    if baseline.get("status") != 200:
        return _finding(
            "NOT_CONFIRMED",
            "LOW",
            wordpress_version,
            f"The login endpoint returned HTTP {baseline.get('status', 0)}, so the parser-differential proof was not sent.",
            {"baseline_status": baseline.get("status", 0), "proof_sent": False},
        )

    marker = f"proofcms-{secrets.token_hex(6)}"
    inert_value = f"< area id={marker} href=/>"
    payload = urllib.parse.urlencode({"log": inert_value, "pwd": "x", "wp-submit": "Log In"})
    response = request(
        login_url,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=payload,
        timeout=timeout,
        proxy=proxy,
    )
    body = str(response.get("body", ""))
    raw_tag = bool(re.search(rf"<area\b[^>]*\bid=[\"']?{re.escape(marker)}(?:[\s>\"'])", body, re.IGNORECASE))
    marker_reflected = marker in body
    evidence = {
        "baseline_status": baseline.get("status"),
        "proof_status": response.get("status", 0),
        "proof_sent": True,
        "marker_reflected": marker_reflected,
        "raw_area_tag": raw_tag,
    }
    if response.get("status") in {401, 403}:
        return _finding(
            "BLOCKED_EXTERNAL",
            "MEDIUM",
            wordpress_version,
            f"The login endpoint rejected the inert reflection probe with HTTP {response.get('status')}.",
            evidence,
        )
    if response.get("status") == 200 and raw_tag:
        return _finding(
            "VULNERABLE",
            "CONFIRMED",
            wordpress_version,
            "The login response normalized an inert '< area>' marker into a raw <area> element, confirming the disclosed parser differential.",
            evidence,
        )
    reflection = "escaped" if marker_reflected else "not reflected"
    return _finding(
        "NOT_CONFIRMED",
        "MEDIUM",
        wordpress_version,
        f"The inert login marker was {reflection}; no executable HTML context was confirmed.",
        evidence,
    )


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    **kwargs: Any,
):
    passive = passive_result(
        advisory_id=CVE_ID, name=NAME, affected_rule=AFFECTED_RULE, fixed_by_branch=FIXED_BY_BRANCH,
        wordpress_version=cms_version, cvss="8.9", vulnerability_type="Cross-Site Scripting (XSS)",
        description="The login screen can reflect attacker-controlled error content without adequate escaping.",
        remediation="Upgrade WordPress to the fixed branch release (7.0.3 or the corresponding backport) and review login-page protections.",
        references=["https://wpscan.com/vulnerability/4594236f-c7ad-41d6-945b-170eaabe2b75/", "https://nvd.nist.gov/vuln/detail/CVE-2026-64638", "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-52p2-r8wf-jcrf"],
    )
    passive.exploit_available = True
    if passive.status == "LIKELY_VULNERABLE":
        passive.status = "NOT_CONFIRMED"
        passive.confidence = "MEDIUM"
        passive.detail = (
            f"WordPress {cms_version} is in the published affected range, but version evidence alone does not "
            "confirm the login parser differential."
        )
    if not run_exploit_check:
        return passive
    if exploit_mode != "safe":
        passive.detail += " This module supports only the inert safe reflection check."
        return passive
    if classify_version(cms_version) not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        passive.detail += " Safe reflection check skipped because the detected version is outside the affected range."
        return passive
    return run_safe_probe(target_url, cms_version, timeout=timeout, proxy=proxy)


def metadata() -> dict[str, Any]:
    result = advisory_metadata(advisory_id=CVE_ID, name=NAME, affected_rule=AFFECTED_RULE, fixed_by_branch=FIXED_BY_BRANCH, cvss="8.9", vulnerability_type="Cross-Site Scripting (XSS)", references=["https://wpscan.com/vulnerability/4594236f-c7ad-41d6-945b-170eaabe2b75/", "https://nvd.nist.gov/vuln/detail/CVE-2026-64638", "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-52p2-r8wf-jcrf"])
    result.update({"exploit_available": True, "exploit_modes": EXPLOIT_MODES})
    return result
