from __future__ import annotations

from typing import Any

CHAIN_ID = "joomla-token-to-upload"
TOKEN_CVE = "CVE-2026-21627"
UPLOAD_CVE = "CVE-2026-105606"
CLEAN = {"PATCHED", "NOT_AFFECTED"}
POSITIVE = {"VULNERABLE", "VULNERABLE_UPLOAD_ONLY", "LIKELY_VULNERABLE"}


def aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    by_cve = {result.get("cve"): result for result in results if result.get("cve")}
    token_status = by_cve.get(TOKEN_CVE, {}).get("status", "MISSING")
    upload_status = by_cve.get(UPLOAD_CVE, {}).get("status", "MISSING")
    components = [TOKEN_CVE, UPLOAD_CVE]

    if token_status in CLEAN or upload_status in CLEAN:
        status, confidence = "NOT_AFFECTED", "HIGH"
        detail = (
            "At least one required token-handling or token-gated upload primitive is patched or "
            "outside its affected range."
        )
        action = "Keep the Tassos Framework and Custom Tables extensions updated."
    elif token_status == "VULNERABLE" and upload_status in {"VULNERABLE", "VULNERABLE_UPLOAD_ONLY"}:
        status, confidence = "LIKELY_VULNERABLE", "HIGH"
        detail = (
            "CVE-2026-21627 confirmed that an unauthenticated session-bound token reached a gadget "
            "write, and CVE-2026-105606 confirmed a guest-token-gated upload. Both token-handling "
            "primitives were confirmed independently; the same token was not replayed end-to-end."
        )
        action = (
            "Upgrade the Tassos Framework and Custom Tables, enforce server-side CSRF validation, "
            "and audit uploaded files."
        )
    elif token_status in POSITIVE and upload_status in POSITIVE:
        status, confidence = "LIKELY_VULNERABLE", "MEDIUM"
        detail = (
            "The Tassos Framework token-handling flaw and the Custom Tables token-gated upload are "
            "both version-affected, but the combined token-to-upload path was not actively confirmed."
        )
        action = (
            "Confirm the token handling and upload path on an authorized lab, then upgrade both "
            "extensions."
        )
    elif token_status == "ERROR" or upload_status == "ERROR":
        status, confidence = "ERROR", "LOW"
        detail = "At least one required token or upload check failed, so the chain could not be assessed."
        action = "Retry the failed checks when the target is reachable."
    else:
        status, confidence = "INCONCLUSIVE", "MEDIUM"
        detail = (
            "The token-handling and token-gated upload prerequisites could not be established "
            "together."
        )
        action = "Verify the Tassos Framework and Custom Tables versions and the upload token gate."

    return {
        "chain": CHAIN_ID,
        "name": "Joomla token-handling weakness to token-gated upload",
        "status": status,
        "confidence": confidence,
        "components": components,
        "component_statuses": {TOKEN_CVE: token_status, UPLOAD_CVE: upload_status},
        "detail": detail,
        "action": action,
    }
