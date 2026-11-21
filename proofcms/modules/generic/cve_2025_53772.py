from __future__ import annotations

from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url
from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2025-53772"
NAME = "IIS Web Deploy msdeploy.axd BinaryFormatter deserialization"
RULE = "Microsoft Web Deploy 4.0 10.0.2000; fixed in 10.0.2001"
FIXED_RULE = "Install the Web Deploy 4.0 10.0.2001 (or later) security update and restrict msdeploy.axd to trusted operators."
HAS_EXPLOIT = False
INTRUSIVE = False
EXPLOIT_MODES: list[str] = []
SAFE_HEADERS = {
    "Content-Type": "application/msdeploy",
    "MSDeploy.RequestId": "proofcms-surface-probe",
    "MSDeploy.Method": "Sync",
    "Content-Length": "0",
}


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return Status.DETECTED_VERSION_UNKNOWN
    if parsed.release[0] != 10:
        return Status.DETECTED_VERSION_UNKNOWN
    if parsed < parse_version_required("10.0.2001"):
        return Status.LIKELY_VULNERABLE
    return Status.PATCHED


def _header(headers: dict[str, Any] | None, name: str) -> str | None:
    for key, value in (headers or {}).items():
        if str(key).lower() == name.lower():
            return str(value)
    return None


def _surface(client: HttpClient, base: str, timeout: int) -> dict[str, Any] | None:
    response = client.get(f"{base}/msdeploy.axd", timeout=timeout)
    if is_transport_error(response):
        return None
    status = int(response.get("status") or 0)
    headers = response.get("headers") or {}
    server = _header(headers, "Server") or ""
    www_auth = (_header(headers, "WWW-Authenticate") or "").lower()
    body = str(response.get("body") or "")
    iis = "iis" in server.lower() or "microsoft-httpapi" in server.lower()
    msdeploy = "msdeploy" in body.lower() or "web deploy" in body.lower()
    # A generic IIS 404 means the handler is not installed. Require an IIS /
    # Web Deploy marker, or an NTLM/Negotiate challenge on the handler path.
    if status == 404:
        return None
    if not (
        iis
        or msdeploy
        or (status in (401, 403) and ("ntlm" in www_auth or "negotiate" in www_auth))
    ):
        return None
    return {
        "path": "/msdeploy.axd",
        "status": status,
        "server": server or None,
        "auth": status in (401, 403),
        "body_hash": response.get("body_hash"),
    }


def _safe_probe(client: HttpClient, base: str, timeout: int) -> dict[str, Any]:
    """Send the required Web Deploy headers without MSDeploy.SyncOptions.

    A real handler answers with the missing-SyncOptions error; this proves the
    endpoint without sending any serialized object.
    """

    response = client.request(
        f"{base}/msdeploy.axd",
        method="POST",
        headers=SAFE_HEADERS,
        data=b"",
        timeout=timeout,
        follow_redirects=False,
    )
    status = int(response.get("status") or 0)
    body = str(response.get("body") or "")
    return {
        "status": status,
        "missing_sync_options": status == 400 and "syncoptions" in body.lower(),
        "auth_required": status in (401, 403),
        "body_hash": response.get("body_hash"),
        "error": response.get("error"),
    }


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    **kwargs: Any,
) -> Finding:
    del cms_version
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    surface = _surface(client, base, timeout)
    # A CMS core version is not a Web Deploy build number. Callers may pass the
    # real build as webdeploy_version; otherwise only the surface is reported.
    version = kwargs.get("webdeploy_version")

    if surface is None:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_DETECTED,
            confidence=Confidence.MEDIUM,
            component="Microsoft IIS Web Deploy (msdeploy.axd)",
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            detail=(
                "No Web Deploy msdeploy.axd surface was observed (a generic IIS 404 is treated as not installed). "
                "No serialized object was sent."
            ),
            action="No action is required unless msdeploy.axd is hosted on a different site or port.",
            evidence={"surface": None},
            vulnerability_type="Deserialization of Untrusted Data",
        )

    proof = _safe_probe(client, base, timeout)
    evidence = {"surface": surface, "safe_probe": proof, "version": version}
    status = classify_version(version) if version else Status.LIKELY_VULNERABLE

    if status == Status.PATCHED:
        detail = f"Web Deploy build {version} is at or beyond the fixed 10.0.2001 release."
        confidence = Confidence.HIGH
        action = "No action is required for this CVE if the build is accurate."
    elif status == Status.DETECTED_VERSION_UNKNOWN:
        detail = (
            f"Web Deploy surface is present, but build {version} is outside the 10.0.2000/10.0.2001 "
            "range or could not be classified."
        )
        confidence = Confidence.MEDIUM
        action = FIXED_RULE
    else:
        detail = (
            "Web Deploy msdeploy.axd is exposed. The affected 10.0.2000 release deserializes the "
            "GZip+Base64 MSDeploy.SyncOptions header with BinaryFormatter; a safe probe confirmed the "
            "handler is reachable, but no serialized payload was sent. The active proof needs a Windows/IIS "
            "Web Deploy 10.0.2000 fixture and valid credentials."
        )
        confidence = Confidence.HIGH if proof["missing_sync_options"] or proof["auth_required"] else Confidence.MEDIUM
        action = FIXED_RULE

    if run_exploit_check:
        detail += " This module is passive-only; the BinaryFormatter payload is intentionally not sent."

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence=confidence,
        component="Microsoft IIS Web Deploy (msdeploy.axd)",
        component_version=version,
        affected_rule=RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=False,
        detail=detail,
        action=action,
        evidence=evidence,
        vulnerability_type="Deserialization of Untrusted Data",
    )


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "generic",
        "name": NAME,
        "component": "Microsoft IIS Web Deploy (msdeploy.axd)",
        "affected_rule": RULE,
        "affected_versions": ["10.0.2000"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "vulnerability_type": "Deserialization of Untrusted Data",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-20",
        "updated": "2026-11-20",
        "required_detectors": [],
        "references": [
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53772",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-53772",
            "https://hawktrace.com/blog/cve-2025-53772/",
        ],
    }
