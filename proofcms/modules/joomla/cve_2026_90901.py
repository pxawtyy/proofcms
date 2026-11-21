from __future__ import annotations

import re
from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-90901"
NAME = "EasyStore Free media image deletion SQL injection"
COMPONENT = "EasyStore Free"
AFFECTED_RULE = "EasyStore Free 1.0.0 through 3.0.0; fixed in 3.0.1"
AFFECTED_VERSIONS = "1.0.0-3.0.0"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]
MANIFEST_PATH = "/administrator/components/com_easystore/easystore.xml"
DETECTOR_KEYS = ("easystore", "com_easystore")
FIXED_VERSION = "3.0.1"


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def _classify(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe(FIXED_VERSION)
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def _version_from_manifest(body: str) -> str | None:
    match = re.search(r"<version>\s*([0-9][0-9A-Za-z.\-+]*)\s*</version>", body or "", re.IGNORECASE)
    return match.group(1) if match else None


def _extension_info(extensions: dict[str, Any] | None) -> dict[str, Any]:
    for key in DETECTOR_KEYS:
        info = (extensions or {}).get(key, {})
        if isinstance(info, dict) and info.get("found"):
            return info
    return {}


def _version_finding(version: str | None, proof_url: str | None = None) -> Finding:
    status = _classify(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected EasyStore Free {version}, within the affected range through 3.0.0. The media image deletion task interpolates the comma-separated ids filter directly into an SQL IN clause."
        action = "Upgrade EasyStore Free to 3.0.1 or newer; it casts ids to integers, uses the ORM whereIn(), and checks the CSRF token."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected EasyStore Free {version}, which validates the media ids and uses the fixed deletion path."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "EasyStore Free was detected, but its version could not be determined from the public manifest."
        action = "Determine the installed EasyStore Free version and upgrade to 3.0.1 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=proof_url, detail=detail, action=action)


def passive_result(extensions: dict[str, Any] | None = None, version: str | None = None) -> Finding:
    info = _extension_info(extensions)
    if version is None and info:
        version = info.get("version")
    if version is None and not info:
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, detail="EasyStore Free was not detected through its public manifest or extension inventory.", action="No action is required unless EasyStore Free is installed but hidden from public detection.")
    return _version_finding(version)


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    del cms_version, run_exploit_check, exploit_mode, aggressive_command, aggressive_args

    extensions = kwargs.get("extensions") or plugins
    version = _extension_info(extensions).get("version")
    url: str | None = None
    if version is None:
        base = normalize_url(target_url)
        url = f"{base}{MANIFEST_PATH}"
        response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
        if is_transport_error(response):
            return Finding(cve=CVE_ID, name=NAME, status="DETECTED_VERSION_UNKNOWN", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=url, detail=f"The EasyStore manifest could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable; transport failure is not evidence of patch status.")
        version = _version_from_manifest(str(response.get("body") or ""))
        if version is None:
            return Finding(cve=CVE_ID, name=NAME, status="DETECTED_VERSION_UNKNOWN", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=url, detail="The EasyStore manifest was reachable but no version could be read.", action="Determine the installed EasyStore Free version and upgrade to 3.0.1 or newer.")
    return _version_finding(version, proof_url=url)


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_versions": [AFFECTED_VERSIONS], "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "SQL Injection", "module_version": "1.0.0", "last_reviewed": "2026-11-21", "updated": "2026-11-21", "required_detectors": [], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-90901", "https://www.cve.org/CVERecord?id=CVE-2026-90901", "https://www.joomshaper.com/"]}
