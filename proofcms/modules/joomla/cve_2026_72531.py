from __future__ import annotations

from typing import Any

from ...core.models import Finding
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2026-72531"
NAME = "Joomla core improper ACL checks for custom fields webservice endpoints"
COMPONENT = "Joomla core com_fields API"
HAS_EXPLOIT = False
INTRUSIVE = False
EXPLOIT_MODES: list[str] = []
AFFECTED_JOOMLA_VERSIONS = ["4.0.0-5.4.7", "6.0.0-6.1.2"]
AFFECTED_RULE = "Joomla 4.0.0-5.4.7 and 6.0.0-6.1.2; a user with core.create but not core.manage can create fields for that component via the API"
FIXED_RULE = "Update to Joomla 5.4.8, 6.1.3, or newer"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    if parse_version_required("4.0.0") <= parsed < parse_version_required("5.4.8"):
        return "LIKELY_VULNERABLE"
    if parse_version_required("6.0.0") <= parsed < parse_version_required("6.1.3"):
        return "LIKELY_VULNERABLE"
    if parsed < parse_version_required("4.0.0"):
        return "NOT_AFFECTED"
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
    confidence = "HIGH" if status in {"LIKELY_VULNERABLE", "PATCHED", "NOT_AFFECTED"} else "MEDIUM"
    details = {
        "LIKELY_VULNERABLE": (
            f"Joomla {joomla_version} checks only core.create in the com_fields API allowAdd; a user "
            "who can create content but not manage the component can create custom fields via the "
            "fields webservice routes."
        ),
        "PATCHED": (
            f"Joomla {joomla_version} requires core.manage in the com_fields API allowAdd before "
            "core.create."
        ),
        "NOT_AFFECTED": f"Joomla {joomla_version} predates the affected com_fields API.",
        "INCONCLUSIVE": "Joomla was detected, but the core version could not be determined.",
    }
    result = Finding(
        cve=CVE_ID, name=NAME, status=status, confidence=confidence,
        component=COMPONENT, component_version=joomla_version, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=details[status],
        action="Upgrade to Joomla 5.4.8, 6.1.3, or newer and review API tokens and custom fields.",
    )
    if run_exploit_check:
        result.detail += (
            " This check is passive-only: the API field-creation proof needs a JSON:API body and an "
            "API token fixture; the lab at labs/cve-2026-72531 has the token and route ready."
        )
    return result


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT,
        "affected_rule": AFFECTED_RULE, "affected_joomla_versions": AFFECTED_JOOMLA_VERSIONS,
        "exploit_available": HAS_EXPLOIT, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE,
        "vulnerability_type": "Improper Access Control",
        "module_version": "1.0.0", "last_reviewed": "2026-11-12", "updated": "2026-11-12",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-72531",
            "https://developer.joomla.org/security-centre/1071-20260804-core-improper-acl-checks-for-custom-fields-webservice-endpoints.html",
        ],
    }
