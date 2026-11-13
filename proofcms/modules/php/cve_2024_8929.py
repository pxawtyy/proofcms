from __future__ import annotations

from typing import Any

from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2024-8929"
NAME = "PHP mysqlnd heap over-read"
RULE = "PHP 8.1 <8.1.31, 8.2 <8.2.26, 8.3 <8.3.14 (and EOL branches)"
TYPE = "Information Disclosure"
CVSS = "7.5"
COMPONENT = "PHP runtime / mysqlnd"


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
            action="Verify the PHP and mysqlnd versions from an authenticated host inventory.",
        )
    version = runtime.get("version")
    status = classify_version(version)
    if status == Status.PATCHED:
        return _finding(
            Status.PATCHED,
            Confidence.HIGH,
            version=version,
            detail=f"PHP {version} includes the mysqlnd fix (8.1.31, 8.2.26, 8.3.14, or newer).",
            action="No action is required for this CVE if the reported version is accurate.",
        )
    if status == Status.DETECTED_VERSION_UNKNOWN:
        return _finding(
            Status.INCONCLUSIVE,
            Confidence.LOW,
            version=version,
            detail="PHP was detected, but the version was not exposed in public responses.",
            action="Verify the PHP version on the host and upgrade to a fixed branch.",
        )
    detail = (
        f"PHP {version} is in the affected range. Version match only: exploitation requires the "
        "target to connect to a hostile MySQL server (or a tampered connection) and a persistent "
        "worker such as PHP-FPM to retain prior query buffers; a remote HTTP request alone cannot "
        f"trigger it. (CVSS {CVSS})"
    )
    if run_exploit_check:
        detail += " This module is passive-only; no MySQL connection is attempted."
    return _finding(
        Status.LIKELY_VULNERABLE,
        Confidence.MEDIUM,
        version=version,
        detail=detail,
        action=(
            "Upgrade PHP to 8.1.31, 8.2.26, 8.3.14, or newer and do not connect production "
            "workers to untrusted MySQL servers."
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
            "https://www.cve.org/CVERecord?id=CVE-2024-8929",
            "https://github.com/php/php-src/security/advisories/GHSA-h35g-vwh6-m678",
        ],
    }
