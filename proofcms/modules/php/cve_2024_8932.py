from __future__ import annotations

from typing import Any

from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2024-8932"
NAME = "PHP ldap_escape 32-bit integer overflow"
RULE = "PHP 8.1 <8.1.31, 8.2 <8.2.26, 8.3 <8.3.14 on 32-bit builds (and EOL branches)"
TYPE = "Out-of-bounds Write / Potential RCE"
CVSS = "9.8"
COMPONENT = "PHP runtime / ldap"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return Status.DETECTED_VERSION_UNKNOWN
    if parsed < parse_version_required("8.1.0"):
        return Status.LIKELY_VULNERABLE
    if parse_version_required("8.1.0") <= parsed < parse_version_required("8.1.31"):
        return Status.LIKELY_VULNERABLE
    if parse_version_required("8.2.0") <= parsed < parse_version_required("8.2.26"):
        return Status.LIKELY_VULNERABLE
    if parse_version_required("8.3.0") <= parsed < parse_version_required("8.3.14"):
        return Status.LIKELY_VULNERABLE
    return Status.PATCHED


def _finding(
    status: str,
    confidence: str,
    *,
    version: str | None,
    detail: str,
    action: str,
) -> Finding:
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence=confidence,
        component=COMPONENT,
        component_version=version,
        affected_rule=RULE,
        exploit_available=False,
        detail=detail,
        action=action,
        vulnerability_type=TYPE,
    )


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    php_runtime: dict[str, Any] | None = None,
    **kwargs: Any,
):
    del target_url, cms_version, timeout, proxy, kwargs
    runtime = php_runtime or {}
    if not runtime.get("detected"):
        return _finding(
            Status.NOT_DETECTED,
            Confidence.LOW,
            version=None,
            detail="PHP was not fingerprinted from public HTTP responses.",
            action="Verify the PHP version and integer size from an authenticated host inventory.",
        )
    version = runtime.get("version")
    int_size = runtime.get("int_size") or runtime.get("php_int_size")
    if int_size is not None and int(int_size) != 4:
        return _finding(
            Status.NOT_AFFECTED,
            Confidence.HIGH,
            version=version,
            detail=(
                f"PHP {version} is a {int_size}-bit build; CVE-2024-8932 only affects "
                "32-bit builds."
            ),
            action="No action is required for this CVE on a 64-bit build.",
        )
    status = classify_version(version)
    if status == Status.PATCHED:
        return _finding(
            Status.PATCHED,
            Confidence.HIGH,
            version=version,
            detail=f"PHP {version} includes the ldap_escape length checks (8.1.31, 8.2.26, 8.3.14, or newer).",
            action="No action is required for this CVE if the reported version is accurate.",
        )
    if status == Status.DETECTED_VERSION_UNKNOWN:
        return _finding(
            Status.INCONCLUSIVE,
            Confidence.LOW,
            version=version,
            detail="PHP was detected, but the version was not exposed in public responses.",
            action="Verify the PHP version and integer size on the host and upgrade to a fixed branch.",
        )
    detail = (
        f"PHP {version} is in the affected range. Version match only: CVE-2024-8932 only "
        "affects 32-bit builds (confirm PHP_INT_SIZE=4), and exploitation requires an "
        "application that calls ldap_escape() on a very long (~1.43 GB) string; the scanner "
        f"does not send it. (CVSS {CVSS})"
    )
    if run_exploit_check:
        detail += " This module is passive-only; no ldap_escape() call is sent."
    return _finding(
        Status.LIKELY_VULNERABLE,
        Confidence.MEDIUM,
        version=version,
        detail=detail,
        action=(
            "Upgrade PHP to 8.1.31, 8.2.26, 8.3.14, or newer, or run the service on a "
            "64-bit build; audit any ldap_escape() call that accepts unbounded input."
        ),
    )


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "php",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": RULE,
        "affected_versions": [
            "<8.1.0 (EOL)",
            "8.1.0-8.1.30",
            "8.2.0-8.2.25",
            "8.3.0-8.3.13",
        ],
        "exploit_available": False,
        "exploit_modes": [],
        "intrusive": False,
        "vulnerability_type": TYPE,
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-13",
        "updated": "2026-11-13",
        "required_detectors": ["php"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2024-8932",
            "https://github.com/php/php-src/security/advisories/GHSA-g665-fm4p-vhff",
        ],
    }
