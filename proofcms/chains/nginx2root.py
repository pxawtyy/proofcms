from __future__ import annotations

from typing import Any

CHAIN_ID = "nginx2root"
# Five independent NGINX exposure paths; the separate kernel escalation is not
# a registered ProofCMS check and is deliberately not included here.
NGINX_CVES = (
    "CVE-2026-123007",
    "CVE-2026-123634",
    "CVE-2026-123633",
    "CVE-2026-121810",
    "CVE-2026-113425",
)
POSITIVE = {"VULNERABLE", "LIKELY_VULNERABLE"}
CLEAN = {"PATCHED", "NOT_AFFECTED"}


def aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Report composition exposure across independent NGINX paths.

    These checks are independent configuration-dependent defects, not a
    replayed multi-stage sequence, so this never reports a confirmed chain.
    """
    by_cve = {result.get("cve"): result for result in results if result.get("cve")}
    statuses = {cve: by_cve.get(cve, {}).get("status", "MISSING") for cve in NGINX_CVES}

    if "ERROR" in statuses.values():
        status, confidence = "ERROR", "LOW"
        detail = "At least one NGINX exposure check failed, so portfolio exposure could not be assessed."
    elif all(value in CLEAN for value in statuses.values()):
        status, confidence = "NOT_AFFECTED", "HIGH"
        detail = "All five NGINX paths are patched or outside their affected ranges."
    elif all(value in POSITIVE for value in statuses.values()):
        status, confidence = "LIKELY_VULNERABLE", "MEDIUM"
        detail = (
            "Five independent NGINX memory-safety paths are version-affected. They are separate "
            "configuration-dependent defects; no cross-defect chain or replayed end-to-end "
            "sequence has been demonstrated. This is composition exposure for remediation "
            "prioritization only."
        )
    elif any(value in POSITIVE for value in statuses.values()):
        status, confidence = "INCONCLUSIVE", "MEDIUM"
        detail = (
            "Some independent NGINX paths are affected, but others could not be established. "
            "No cross-defect chain has been demonstrated."
        )
    else:
        status, confidence = "INCONCLUSIVE", "MEDIUM"
        detail = "The NGINX exposure paths could not be established together."

    return {
        "chain": CHAIN_ID,
        "name": "independent NGINX memory-safety exposure (portfolio)",
        "status": status,
        "confidence": confidence,
        "components": list(NGINX_CVES),
        "component_statuses": statuses,
        "detail": detail,
        "action": (
            "Upgrade NGINX to 1.31.9 or a newer supported release across all affected layers, "
            "and patch any co-resident kernel issue independently. Disabling HTTP/2 blocks only "
            "the two HTTP/2 paths; it does not address the resolver, HTTP/3 or mail paths."
        ),
    }
