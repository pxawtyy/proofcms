from __future__ import annotations

from typing import Any

CHAIN_ID = "joomla-session-to-upload"
SESSION_CVES = ("CVE-2026-90907", "CVE-2026-48897", "CVE-2026-92227")
UPLOAD_CVE = "CVE-2026-105603"
CLEAN = {"PATCHED", "NOT_AFFECTED"}
UPLOAD_POSITIVE = {"VULNERABLE", "VULNERABLE_UPLOAD_ONLY", "LIKELY_VULNERABLE"}


def _session_state(statuses: dict[str, str]) -> str:
    if any(status == "VULNERABLE" for status in statuses.values()):
        return "VULNERABLE"
    if any(status == "LIKELY_VULNERABLE" for status in statuses.values()):
        return "LIKELY_VULNERABLE"
    if all(status in CLEAN for status in statuses.values()):
        return "NOT_AFFECTED"
    if any(status == "ERROR" for status in statuses.values()):
        return "ERROR"
    return "INCONCLUSIVE"


def _best_session(statuses: dict[str, str]) -> str:
    for status in ("VULNERABLE", "LIKELY_VULNERABLE"):
        for cve, value in statuses.items():
            if value == status:
                return cve
    return "none"


def aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    by_cve = {result.get("cve"): result for result in results if result.get("cve")}
    session_statuses = {
        cve: by_cve.get(cve, {}).get("status", "MISSING") for cve in SESSION_CVES
    }
    upload_status = by_cve.get(UPLOAD_CVE, {}).get("status", "MISSING")
    session_state = _session_state(session_statuses)
    best_session = _best_session(session_statuses)
    components = list(SESSION_CVES) + [UPLOAD_CVE]

    if upload_status in CLEAN:
        status, confidence = "NOT_AFFECTED", "HIGH"
        detail = (
            "A session-acquisition primitive may exist, but the DJ-Classifieds authenticated avatar "
            "upload is patched or outside its affected range."
        )
        action = "Upgrade DJ-Classifieds and keep the avatar content/type validation enabled."
    elif session_state == "NOT_AFFECTED":
        status, confidence = "NOT_AFFECTED", "HIGH"
        detail = (
            "The authenticated avatar upload is affected, but every session-acquisition primitive "
            "in this chain is patched or outside its affected range."
        )
        action = "Keep Joomla patched and enforce session invalidation on login and MFA completion."
    elif session_state == "VULNERABLE" and upload_status in {"VULNERABLE", "VULNERABLE_UPLOAD_ONLY"}:
        status, confidence = "LIKELY_VULNERABLE", "HIGH"
        detail = (
            f"Session acquisition via {best_session} and the DJ-Classifieds authenticated avatar "
            "upload were both confirmed independently. The chain was not executed as one session "
            "end-to-end."
        )
        action = (
            "Disable unauthenticated profile creation, invalidate sessions on login/MFA, upgrade "
            "DJ-Classifieds, and audit wp-content/uploads for unexpected files."
        )
    elif session_state in {"VULNERABLE", "LIKELY_VULNERABLE"} and upload_status in UPLOAD_POSITIVE:
        status, confidence = "LIKELY_VULNERABLE", "MEDIUM"
        detail = (
            f"Session acquisition via {best_session} is {session_state.lower().replace('_', ' ')} "
            f"and the DJ-Classifieds avatar upload is {upload_status.lower().replace('_', ' ')}. "
            "Both prerequisites are present, but the combined session-to-upload path was not "
            "actively confirmed."
        )
        action = (
            "Confirm the upload with a registered test account, upgrade DJ-Classifieds, and audit "
            "uploaded avatars."
        )
    elif session_state == "ERROR" or upload_status == "ERROR":
        status, confidence = "ERROR", "LOW"
        detail = "At least one required session or upload check failed, so the chain could not be assessed."
        action = "Retry the failed checks when the target is reachable."
    else:
        status, confidence = "INCONCLUSIVE", "MEDIUM"
        detail = (
            "The session-acquisition and authenticated-upload prerequisites could not be established "
            "together."
        )
        action = "Verify guest registration, MFA/session handling, and the DJ-Classifieds upload path."

    return {
        "chain": CHAIN_ID,
        "name": "Joomla session acquisition to authenticated avatar upload",
        "status": status,
        "confidence": confidence,
        "components": components,
        "component_statuses": {**session_statuses, UPLOAD_CVE: upload_status},
        "detail": detail,
        "action": action,
    }
