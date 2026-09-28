from __future__ import annotations

from typing import Any

CHAIN_ID = "wp2shell"
REQUIRED_CVES = ("CVE-2026-63030", "CVE-2026-60137")
POSITIVE = {"VULNERABLE", "LIKELY_VULNERABLE"}


def aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    by_cve = {result.get("cve"): result for result in results}
    components = [by_cve.get(cve) for cve in REQUIRED_CVES]
    statuses = [component.get("status") if component else "INCONCLUSIVE" for component in components]

    if "ERROR" in statuses:
        status, confidence = "ERROR", "LOW"
        detail = "At least one required CVE check failed, so wp2shell exposure could not be assessed."
    elif any(status in {"PATCHED", "NOT_AFFECTED"} for status in statuses):
        status, confidence = "NOT_AFFECTED", "HIGH"
        detail = "At least one required wp2shell component is patched or outside its affected range."
    elif all(status in POSITIVE for status in statuses) and "VULNERABLE" in statuses:
        status, confidence = "VULNERABLE", "CONFIRMED"
        detail = (
            "The safe nested-batch timing proof confirmed the combined route-confusion and SQL injection path. "
            "This establishes wp2shell chain exposure without executing the RCE stage."
        )
    elif all(status in POSITIVE for status in statuses):
        status, confidence = "LIKELY_VULNERABLE", "HIGH"
        detail = "Both CVE components are version-affected, but the combined path was not actively confirmed."
    else:
        status, confidence = "INCONCLUSIVE", "MEDIUM"
        detail = "One or more wp2shell prerequisites could not be established."

    return {
        "chain": CHAIN_ID,
        "name": "wp2shell pre-authentication RCE chain",
        "status": status,
        "confidence": confidence,
        "components": list(REQUIRED_CVES),
        "component_statuses": dict(zip(REQUIRED_CVES, statuses, strict=True)),
        "detail": detail,
        "action": "Upgrade affected WordPress branches to 6.9.5, 7.0.2, or a newer supported release.",
    }
