from __future__ import annotations

from typing import Any

from ...core.models import Finding
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2017-14596"
NAME = "Joomla core LDAP authentication injection"
COMPONENT = "Joomla core LDAP authentication plugin"
HAS_EXPLOIT = False
INTRUSIVE = False
EXPLOIT_MODES: list[str] = []
AFFECTED_JOOMLA_VERSIONS = ["1.5.0-3.7.5"]
AFFECTED_RULE = "Joomla before 3.8.0 with the LDAP authentication plugin enabled"
FIXED_RULE = "Update to Joomla 3.8.0 or newer"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    if parsed < parse_version_required("3.8.0"):
        return "LIKELY_VULNERABLE"
    return "PATCHED"


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aggressive_command: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Finding:
    status = classify_version(joomla_version)
    confidence = "HIGH" if status in {"LIKELY_VULNERABLE", "PATCHED"} else "MEDIUM"
    details = {
        "LIKELY_VULNERABLE": (
            f"Joomla {joomla_version} does not escape the username/password before embedding them "
            "in the LDAP authentication query; a live proof needs the LDAP plugin and an LDAP "
            "directory."
        ),
        "PATCHED": f"Joomla {joomla_version} escapes LDAP filter values in the authentication plugin.",
        "INCONCLUSIVE": "Joomla was detected, but the core version could not be determined.",
    }
    result = Finding(
        cve=CVE_ID, name=NAME, status=status, confidence=confidence,
        component=COMPONENT, component_version=joomla_version, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=details[status],
        action="Upgrade to Joomla 3.8.0 or newer and review LDAP authentication usage.",
    )
    if run_exploit_check:
        result.detail += (
            " This check is passive-only: the LDAP injection proof requires an LDAP server fixture "
            "and the Joomla 3.7.5/3.8.0 packages."
        )
    return result


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT,
        "affected_rule": AFFECTED_RULE, "affected_joomla_versions": AFFECTED_JOOMLA_VERSIONS,
        "exploit_available": HAS_EXPLOIT, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE,
        "vulnerability_type": "Information Disclosure",
        "module_version": "1.0.0", "last_reviewed": "2026-11-12", "updated": "2026-11-12",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2017-14596",
            "https://developer.joomla.org/security-centre/711-20170902-core-ldap-information-disclosure.html",
        ],
    }
