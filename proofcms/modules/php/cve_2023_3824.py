from __future__ import annotations

from typing import Any

from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2023-3824"
NAME = "PHP phar directory entry buffer overflow"
RULE = "PHP 8.0 <8.0.30, 8.1 <8.1.22, 8.2 <8.2.8"
TYPE = "Buffer Overflow / Potential RCE"
CVSS = "9.4"
COMPONENT = "PHP runtime / phar"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return Status.DETECTED_VERSION_UNKNOWN
    if parsed < parse_version_required("8.0.0"):
        return Status.NOT_AFFECTED
    if parse_version_required("8.0.0") <= parsed < parse_version_required("8.0.30"):
        return Status.LIKELY_VULNERABLE
    if parse_version_required("8.1.0") <= parsed < parse_version_required("8.1.22"):
        return Status.LIKELY_VULNERABLE
    if parse_version_required("8.2.0") <= parsed < parse_version_required("8.2.8"):
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
            action="Verify the PHP version from an authenticated host inventory.",
        )
    version = runtime.get("version")
    status = classify_version(version)
    if status == Status.PATCHED:
        return _finding(
            Status.PATCHED,
            Confidence.HIGH,
            version=version,
            detail=f"PHP {version} includes the phar_dir_read() bounds fix.",
            action="No action is required for this CVE if the reported version is accurate.",
        )
    if status == Status.NOT_AFFECTED:
        return _finding(
            Status.NOT_AFFECTED,
            Confidence.HIGH,
            version=version,
            detail=f"PHP {version} predates the affected 8.0/8.1/8.2 branches.",
            action="No action is required for this CVE.",
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
        "application to load a crafted phar archive and list a directory entry inside it; the "
        "scanner does not upload archives. The lab PoC creates 4095/4096-byte entry names: the "
        "vulnerable readdir returns a 4096-byte string, while the fixed build rejects it with "
        f"false. (CVSS {CVSS})"
    )
    if run_exploit_check:
        detail += " This module is passive-only; no phar is uploaded."
    return _finding(
        Status.LIKELY_VULNERABLE,
        Confidence.MEDIUM,
        version=version,
        detail=detail,
        action="Upgrade PHP to 8.0.30, 8.1.22, 8.2.8, or newer and avoid untrusted phar archives.",
    )


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "php",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": RULE,
        "affected_versions": [
            "8.0.0-8.0.29",
            "8.1.0-8.1.21",
            "8.2.0-8.2.7",
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
            "https://www.cve.org/CVERecord?id=CVE-2023-3824",
            "https://github.com/php/php-src/security/advisories/GHSA-jqcx-ccgc-xwhv",
        ],
    }
