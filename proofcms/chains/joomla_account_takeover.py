from __future__ import annotations

from typing import Any

CHAIN_ID = "joomla-account-takeover"
CVES = ("CVE-2016-8870", "CVE-2016-8869")


def aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    selected = {result.get("cve"): result for result in results if result.get("cve") in CVES}
    statuses = {cve: selected.get(cve, {}).get("status", "MISSING") for cve in CVES}
    if all(statuses[cve] == "LIKELY_VULNERABLE" for cve in CVES):
        status, confidence = "LIKELY_VULNERABLE", "HIGH"
        detail = (
            "Both historical registration flaws match the detected Joomla version: disabled-registration account "
            "creation and attacker-controlled group assignment form the published account-takeover chain. No user "
            "was created."
        )
    elif any(statuses[cve] in {"PATCHED", "NOT_AFFECTED"} for cve in CVES):
        status, confidence = "NOT_AFFECTED", "HIGH"
        detail = "At least one required registration flaw is patched or outside its affected range."
    elif any(statuses[cve] == "ERROR" for cve in CVES):
        status, confidence = "ERROR", "LOW"
        detail = "At least one required CVE check failed."
    else:
        status, confidence = "INCONCLUSIVE", "MEDIUM"
        detail = "Both registration-chain prerequisites could not be established."
    return {
        "chain": CHAIN_ID,
        "name": "Joomla unauthenticated account-takeover chain",
        "status": status,
        "confidence": confidence,
        "components": list(CVES),
        "detail": detail,
        "action": "Upgrade Joomla to 3.6.4 or a supported release and audit all privileged accounts.",
    }
