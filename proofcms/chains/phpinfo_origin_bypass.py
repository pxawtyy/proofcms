from __future__ import annotations

from typing import Any

CHAIN_ID = "phpinfo-to-origin-bypass"
RECON_CVES = ("PROOFCMS-PHPINFO-EXPOSURE", "PROOFCMS-ORIGIN-DIRECT-ACCESS")
PHP_CVES = ("CVE-2019-11043", "CVE-2024-4577")
CONFIRMED = {"VULNERABLE"}
POSITIVE = {"VULNERABLE", "LIKELY_VULNERABLE"}
CLEAN = {"PATCHED", "NOT_AFFECTED"}


def _php_state(statuses: dict[str, str]) -> str:
    if any(status == "VULNERABLE" for status in statuses.values()):
        return "VULNERABLE"
    if any(status == "LIKELY_VULNERABLE" for status in statuses.values()):
        return "LIKELY_VULNERABLE"
    if all(status in CLEAN for status in statuses.values()):
        return "NOT_AFFECTED"
    if any(status == "ERROR" for status in statuses.values()):
        return "ERROR"
    return "INCONCLUSIVE"


def aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    by_cve = {result.get("cve"): result for result in results if result.get("cve")}
    recon_statuses = {
        cve: by_cve.get(cve, {}).get("status", "MISSING") for cve in RECON_CVES
    }
    php_statuses = {
        cve: by_cve.get(cve, {}).get("status", "MISSING") for cve in PHP_CVES
    }
    recon_ready = all(status in CONFIRMED for status in recon_statuses.values())
    php_state = _php_state(php_statuses)
    components = list(RECON_CVES) + list(PHP_CVES)

    if php_state == "NOT_AFFECTED":
        status, confidence = "NOT_AFFECTED", "HIGH"
        detail = (
            "phpinfo/origin exposure may still exist, but both PHP-FPM/CGI primitives are patched "
            "or outside their affected ranges, so the RCE stage is not available."
        )
        action = "Keep PHP patched; remove phpinfo and restrict direct origin access as defense in depth."
    elif php_state == "ERROR":
        status, confidence = "ERROR", "LOW"
        detail = "At least one PHP-FPM/CGI prerequisite check failed, so the chain could not be assessed."
        action = "Retry the PHP checks when the target is reachable."
    elif recon_ready and php_state == "VULNERABLE":
        status, confidence = "LIKELY_VULNERABLE", "HIGH"
        detail = (
            "phpinfo disclosure and direct origin access were both confirmed, and a PHP-FPM/CGI "
            "RCE primitive is confirmed on the detected runtime. The three exposures were verified "
            "independently; the chain was not executed end-to-end."
        )
        action = (
            "Remove phpinfo, firewall the origin to the edge provider, and upgrade PHP-FPM/CGI "
            "to a fixed release."
        )
    elif recon_ready and php_state == "LIKELY_VULNERABLE":
        status, confidence = "LIKELY_VULNERABLE", "MEDIUM"
        detail = (
            "phpinfo and origin access are confirmed, and the PHP runtime matches an affected "
            "FPM/CGI range, but the RCE primitive was not actively confirmed. The chain was not "
            "executed end-to-end."
        )
        action = (
            "Remove phpinfo, firewall the origin, upgrade PHP, and run the PHP-CVE safe proof "
            "against the origin on an authorized lab."
        )
    elif php_state in POSITIVE:
        status, confidence = "INCONCLUSIVE", "MEDIUM"
        detail = (
            "A PHP-FPM/CGI RCE primitive is affected, but the phpinfo and/or direct-origin "
            "prerequisites were not observed. The chain-specific origin-bypass path is therefore "
            "not established."
        )
        action = "Verify whether phpinfo is exposed and whether the origin accepts direct requests."
    else:
        status, confidence = "INCONCLUSIVE", "MEDIUM"
        detail = (
            "The phpinfo/origin prerequisites and the PHP-FPM/CGI version could not be established "
            "together."
        )
        action = "Re-run with PHP runtime detection and origin verification enabled."

    return {
        "chain": CHAIN_ID,
        "name": "phpinfo and direct-origin exposure to PHP-FPM/CGI RCE",
        "status": status,
        "confidence": confidence,
        "components": components,
        "component_statuses": {**recon_statuses, **php_statuses},
        "detail": detail,
        "action": action,
    }
