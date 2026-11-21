from __future__ import annotations

import re
from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-117543"
NAME = "jDownloads external download URL redirect SSRF"
COMPONENT = "jDownloads"
AFFECTED_RULE = "jDownloads 1.0.0 through 4.1.7; fixed in 4.1.8"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe", "aggressive"]
DOWNLOAD_PATH = "/index.php?option=com_jdownloads&task=download.send"


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("4.1.8")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("jdownloads", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="jDownloads was not detected.", action="No action is required unless jDownloads is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected jDownloads {version}, within the affected range below 4.1.8. External download retrieval follows HTTP redirects."
        action = "Upgrade jDownloads to 4.1.8 or newer."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected jDownloads {version}, which disables redirects for external download retrieval."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "jDownloads was detected, but its version could not be determined."
        action = "Determine the installed jDownloads version and upgrade to 4.1.8 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def run_aggressive_probe(
    target_url: str,
    download_id: int = 1,
    catid: int = 2,
    marker: str = "PROOFCMS_SSRF_CANARY_MARKER",
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Request a seeded external download and look for the canary body.

    jDownloads 4.1.7 validates the original ``extern_file`` URL but lets PHP's
    ``readfile()`` / ``get_headers()`` follow HTTP redirects. A download whose
    URL points at an allowed redirector therefore fetches the redirect target
    and streams it back. 4.1.8 disables redirects in ``getUrlFilesize()``,
    ``getMimeTypeRemote()`` and the delivery ``fopen()``.
    """
    base = normalize_url(target_url)
    url = f"{base}{DOWNLOAD_PATH}&id={download_id}&catid={catid}&m=0"
    response = HttpClient(timeout=timeout, proxy=proxy).request(url, method="GET", follow_redirects=False, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The external download request failed in transit ({transport_error_detail(response)}).", action="Retry when the target is reachable.")

    body = response.get("body") or ""
    evidence = {
        "download_id": download_id,
        "catid": catid,
        "status": response.get("status"),
        "marker": marker,
        "marker_found": marker in body,
        "body_length": len(body),
        "content_type": (response.get("headers") or {}).get("content-type", "") if isinstance(response.get("headers"), dict) else "",
    }
    if marker in body:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=url,
            evidence=evidence,
            detail=(
                "The external download followed the redirector to an internal canary and streamed its body "
                "back to the requester. The original URL passed validation; the redirect target was not checked."
            ),
            action="Upgrade jDownloads to 4.1.8 or newer and review external download URLs.",
        )
    if response.get("status") in (301, 302, 303, 307, 308):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="HIGH", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, evidence=evidence, detail=f"The external download returned HTTP {response.get('status')} and did not follow the redirect; 4.1.8 disables redirect following.", action="Upgrade affected jDownloads versions even when the external proof is inconclusive.")
    status = "BLOCKED_EXTERNAL" if response.get("status") in (401, 403, 404) else "NOT_CONFIRMED"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, evidence=evidence, detail=f"The download request returned HTTP {response.get('status')} without the canary marker; seed a public external download and a controlled redirector/canary first.", action="Upgrade affected jDownloads versions even when the external proof is inconclusive.")


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}/index.php?option=com_jdownloads"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The jDownloads page could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The jDownloads page is reachable; the external download request was not sent in safe mode.", action="Use aggressive mode with a seeded external download and a controlled redirector on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because jDownloads was not detected as potentially affected."
            return passive
        download_value = aggressive_value(aggressive_args, aggressive_command, "download_id")
        catid_value = aggressive_value(aggressive_args, aggressive_command, "catid")
        result = run_aggressive_probe(
            target_url,
            download_id=int(download_value) if download_value and download_value.isdigit() else 1,
            catid=int(catid_value) if catid_value and catid_value.isdigit() else 2,
            marker=aggressive_value(aggressive_args, aggressive_command, "marker") or "PROOFCMS_SSRF_CANARY_MARKER",
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (jDownloads reachability) and aggressive (external download redirect) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def cleanup(
    target_url: str,
    *,
    timeout: int = 12,
    proxy: str | None = None,
    aggressive_args: dict | None = None,
    aggressive_command: str | None = None,
) -> dict:
    """Verify the uploaded artifact and report any manual removal step."""
    from ...core.cleanup import cleanup_http_artifact

    return cleanup_http_artifact(
        target_url,
        timeout=timeout,
        proxy=proxy,
        aggressive_args=aggressive_args,
        aggressive_command=aggressive_command,
    )


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Server-Side Request Forgery (SSRF)", "module_version": "1.0.0", "last_reviewed": "2026-11-16", "updated": "2026-11-16", "required_detectors": ["jdownloads"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-117543", "https://www.jdownloads.com", "https://mysites.guru/vulnerabilities/CVE-2026-117543"]}
