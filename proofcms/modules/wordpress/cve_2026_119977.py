from __future__ import annotations

import re
from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding

CVE_ID = "CVE-2026-119977"
NAME = "WordPress core upgrade-window config write"
COMPONENT = "WordPress core"
AFFECTED_RULE = "WordPress 4.7.0 through 7.1.3; fixed in 7.1.4"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]
README_PATH = "/readme.html"
FIRST_AFFECTED = "4.7.0"
FIXED_VERSION = "7.1.4"


def _numeric_version(version: str | None) -> str | None:
    match = re.search(r"(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def _version_tuple(version: str | None, length: int = 4) -> tuple[int, ...] | None:
    parsed = _numeric_version(version)
    if not parsed:
        return None
    try:
        parts = [int(part) for part in parsed.split(".")]
    except ValueError:
        return None
    return tuple((parts + [0] * length)[:length])


def _classify(version: str | None) -> str:
    current = _version_tuple(version)
    if current is None:
        return "DETECTED_VERSION_UNKNOWN"
    lower = _version_tuple(FIRST_AFFECTED) or (4, 7, 0, 0)
    fixed = _version_tuple(FIXED_VERSION) or (7, 1, 4, 0)
    return "LIKELY_VULNERABLE" if lower <= current < fixed else "NOT_AFFECTED"


def _version_from_body(body: str) -> str | None:
    match = re.search(r"Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)*)", body or "", re.IGNORECASE)
    return match.group(1) if match else None


def passive_result(plugins: dict[str, Any] | None = None, version: str | None = None) -> Finding:
    del plugins  # core advisory - no plugin detector map is involved
    status = _classify(version)
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence="HIGH" if version else "MEDIUM", component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=f"Detected WordPress core {version or '(version unknown)'}; 7.1.3 and earlier use a predictable wp-content/upgrade staging path and lack the config-write hardening added in 7.1.4.", action="Upgrade WordPress core to 7.1.4 or newer. This module reports a version-based likelihood only; the staged installer write needs local upgrade-state control, so no reliable remote active oracle exists.")


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None, plugins: dict[str, Any] | None = None, version: str | None = None) -> Finding:
    del plugins  # core advisory - no plugin detector map is involved
    base = normalize_url(target_url)
    url = f"{base}{README_PATH}"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The core readme could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    if response.get("status") != 200:
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The core readme returned HTTP {response.get('status')}; no WordPress version was disclosed.", action="No action is required unless the readme is hidden by a different path.")
    detected = _version_from_body(str(response.get("body") or ""))
    effective = version if version is not None else detected
    status = _classify(effective)
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence="MEDIUM", component=COMPONENT, component_version=effective, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"Read WordPress core version {effective or '(unknown)'} from the public readme.html; no installer or staging request was sent in safe mode.", action="Upgrade to WordPress 7.1.4 or newer if the detected version is affected.")


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    del aggressive_command, aggressive_args
    passive = passive_result(plugins, version=cms_version)
    if not run_exploit_check:
        return passive
    if exploit_mode != "safe":
        passive.detail += " This module supports only the safe (public core version) probe; it has no remote active oracle."
        return passive
    result = run_safe_probe(target_url, timeout=timeout, proxy=proxy, plugins=plugins, version=cms_version)
    result.detail += " This module is lab-confirmed but exposes only a passive version check because the config write needs staged upgrade state."
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "wordpress", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_versions": ["4.7.0-7.1.3"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Upgrade-Window Config Write / RCE", "module_version": "1.0.0", "last_reviewed": "2026-11-21", "updated": "2026-11-21", "required_detectors": [], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-119977", "https://wordpress.org/news/2026/", "https://core.trac.wordpress.org/"]}
