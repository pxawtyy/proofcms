from __future__ import annotations

import re
from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-100750"
NAME = "Modules Anywhere Pro module parameter override LFI/SSRF"
COMPONENT = "Modules Anywhere Pro"
AFFECTED_RULE = "Modules Anywhere Pro 1.5.0 through 9.0.5; fixed in 10.0.0"
AFFECTED_VERSIONS = "1.5.0-9.0.5"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]
MANIFEST_PATH = "/plugins/system/modulesanywhere/modulesanywhere.xml"
DETECTOR_KEYS = ("modulesanywhere", "regularlabs", "plg_system_modulesanywhere")
FIXED_VERSION = "10.0.0"


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
        detail = f"Detected Modules Anywhere Pro {version}, within the affected range through 9.0.5. Unrecognised {{module ...}} tag attributes are written onto the module params, letting a content author override settings such as rssurl and read local or network URLs."
        action = "Upgrade Modules Anywhere Pro to 10.0.0 or newer; it restricts parameter overrides to trusted sources by default."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected Modules Anywhere Pro {version}, which gates module parameter overrides behind a trusted-source check."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "Modules Anywhere Pro was detected, but its version could not be determined from the public manifest."
        action = "Determine the installed Modules Anywhere Pro version and upgrade to 10.0.0 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=proof_url, detail=detail, action=action)


def passive_result(extensions: dict[str, Any] | None = None, version: str | None = None) -> Finding:
    info = _extension_info(extensions)
    if version is None and info:
        version = info.get("version")
    if version is None and not info:
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, detail="Modules Anywhere Pro was not detected through its public manifest or extension inventory.", action="No action is required unless Modules Anywhere Pro is installed but hidden from public detection.")
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
            return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=url, detail=f"The Modules Anywhere manifest could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable; transport failure is not evidence of patch status.")
        status_code = response.get("status")
        body = str(response.get("body") or "")
        if status_code == 404:
            return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=url, detail="The Modules Anywhere manifest returned HTTP 404; the extension is not publicly installed.", action="No action is required unless Modules Anywhere Pro is installed but hidden from public detection.")
        if status_code in (401, 403):
            return Finding(cve=CVE_ID, name=NAME, status="DETECTED_VERSION_UNKNOWN", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=url, detail=f"The Modules Anywhere manifest returned HTTP {status_code}; access is denied but the path exists.", action="Determine the installed Modules Anywhere Pro version through an authorized channel.")
        version = _version_from_manifest(body)
        if status_code != 200 or (version is None and "<extension" not in body.lower() and "<name" not in body.lower()):
            return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=url, detail=f"The manifest path returned HTTP {status_code} without a Modules Anywhere manifest body.", action="No action is required unless Modules Anywhere Pro is installed but hidden from public detection.")
        if version is None:
            return Finding(cve=CVE_ID, name=NAME, status="DETECTED_VERSION_UNKNOWN", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=url, detail="The Modules Anywhere manifest was reachable but no version could be read.", action="Determine the installed Modules Anywhere Pro version and upgrade to 10.0.0 or newer.")
    return _version_finding(version, proof_url=url)


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_versions": [AFFECTED_VERSIONS], "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Local File Inclusion / SSRF", "module_version": "1.0.0", "last_reviewed": "2026-11-21", "updated": "2026-11-21", "required_detectors": ["modulesanywhere"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-100750", "https://www.cve.org/CVERecord?id=CVE-2026-100750", "https://www.regularlabs.com/extensions/modulesanywhere"]}
