from __future__ import annotations

from typing import Any

from ...core.versions import parse_version_required, parse_version_safe
from .advisory import passive_core_finding, passive_only_check

CVE_ID = "CVE-2014-7984"
NAME = "Joomla core GMail authentication bypass"
AFFECTED_RULE = "Joomla 2.5.x through 2.5.18 and 3.x through 3.2.2 with the GMail auth plugin"
REMEDIATION = (
    "Upgrade to Joomla 2.5.19, 3.2.3, or a newer supported release; the GMail auth plugin was "
    "removed in Joomla 4.0."
)


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    if parse_version_required("2.5.0") <= parsed < parse_version_required("2.5.19"):
        return "LIKELY_VULNERABLE"
    if parse_version_required("3.0.0") <= parsed < parse_version_required("3.2.3"):
        return "LIKELY_VULNERABLE"
    if parsed >= parse_version_required("3.2.3") or parsed >= parse_version_required("2.5.19"):
        return "PATCHED"
    return "NOT_AFFECTED"


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    **kwargs: Any,
) -> Any:
    finding = passive_core_finding(
        cve=CVE_ID,
        name=NAME,
        affected_rule=AFFECTED_RULE,
        joomla_version=joomla_version,
        classify=classify_version,
        remediation=REMEDIATION,
    )
    if joomla_version and finding.status == "LIKELY_VULNERABLE":
        finding.detail += (
            " An active proof needs the legacy GMail authentication plugin enabled and an "
            "authentication service; the public surface does not disclose that configuration."
        )
    return passive_only_check(finding, run_exploit_check)


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": "Joomla core",
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": ["2.5.0-2.5.18", "3.0.0-3.2.2"],
        "exploit_available": False,
        "exploit_modes": [],
        "intrusive": False,
        "vulnerability_type": "Authentication Bypass",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-22",
        "updated": "2026-11-22",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2014-7984",
            "https://developer.joomla.org/security/581-20140304-core-unauthorised-logins.html",
        ],
    }
