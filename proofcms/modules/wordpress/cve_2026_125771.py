from __future__ import annotations

import re
from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding

CVE_ID = "CVE-2026-125771"
NAME = "MCP Server for WordPress connection-scope bypass"
COMPONENT = "MCP Server for WordPress"
AFFECTED_RULE = "MCP Server for WordPress <= 2.0.3; fixed in 2.0.4"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]
PLUGIN_SLUG = "ai-workflow-automation-ai-agent-hub"
README_PATH = f"/wp-content/plugins/{PLUGIN_SLUG}/readme.txt"
FIXED_VERSION = "2.0.4"
PLUGIN_KEYS = ("ai_workflow_automation", "mcp_server", "ai_workflow_automation_ai_agent_hub")


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
    fixed = _version_tuple(FIXED_VERSION) or (2, 0, 4, 0)
    return "LIKELY_VULNERABLE" if current < fixed else "NOT_AFFECTED"


def _version_from_body(body: str) -> str | None:
    match = re.search(r"Stable tag:\s*([0-9]+(?:\.[0-9]+)+)", body or "", re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(r"^\s*\*?\s*Version:\s*([0-9]+(?:\.[0-9]+)+)", body or "", re.IGNORECASE | re.MULTILINE)
    return match.group(1) if match else None


def _plugin_info(plugins: dict[str, Any] | None) -> dict[str, Any]:
    for key in PLUGIN_KEYS:
        info = (plugins or {}).get(key)
        if isinstance(info, dict):
            return info
    return {}


def passive_result(plugins: dict[str, Any] | None = None, version: str | None = None) -> Finding:
    info = _plugin_info(plugins) if plugins else {}
    if version is None and info.get("found"):
        version = info.get("version")
    if plugins and version is None and not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="MCP Server for WordPress was not detected through its public asset paths or the supplied plugin detector map.", action="No action is required unless the plugin is installed but hidden from public detection.")
    status = _classify(version)
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence="HIGH" if version else "MEDIUM", component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=f"Detected MCP Server for WordPress {version or '(version unknown)'}; 2.0.3 guards only tool hooks, so abilities still run through prompts/get and resources/read despite a Read-only or paused connection.", action="Upgrade the plugin to 2.0.4 or newer. This module reports a version-based likelihood only; the bypass needs an authenticated MCP connection, so no reliable remote active oracle exists.")


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None, plugins: dict[str, Any] | None = None, version: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}{README_PATH}"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=url, detail=f"The plugin manifest could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    detected = _version_from_body(str(response.get("body") or ""))
    effective = version
    if effective is None and plugins:
        info = _plugin_info(plugins)
        if info.get("found"):
            effective = info.get("version")
    if effective is None:
        effective = detected
    status = _classify(effective)
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence="MEDIUM", component=COMPONENT, component_version=effective, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=url, detail=f"Read MCP Server for WordPress version {effective or '(unknown)'} from the public manifest; no MCP request was sent in safe mode.", action="Upgrade to 2.0.4 or newer if the detected version is affected.")


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    del aggressive_command, aggressive_args
    passive = passive_result(plugins, version=cms_version)
    if not run_exploit_check:
        return passive
    if exploit_mode != "safe":
        passive.detail += " This module supports only the safe (public manifest version) probe; it has no remote active oracle."
        return passive
    result = run_safe_probe(target_url, timeout=timeout, proxy=proxy, plugins=plugins, version=cms_version)
    result.detail += " This module is lab-confirmed but exposes only a passive version check because the bypass requires an authenticated MCP connection."
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "wordpress", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_versions": ["<=2.0.3"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Improper Access Control", "module_version": "1.0.0", "last_reviewed": "2026-11-21", "updated": "2026-11-21", "required_detectors": [], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-125771", "https://wordpress.org/plugins/ai-workflow-automation-ai-agent-hub/", "https://github.com/advisories/GHSA-mcp-wp-connection-scope"]}
