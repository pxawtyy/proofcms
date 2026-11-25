from __future__ import annotations

from typing import Any

from ...core.models import Finding, Status
from ...core.versions import parse_version_required, parse_version_safe
from .advisory import passive_core_finding

CVE_ID = "CVE-2026-129393"
NAME = "Joomla core RCE through media custom field parameters"
RULE = (
    "Joomla 4.0.0-5.4.10 and 6.0.0-6.2.0; the media custom field directory/preview "
    "parameters are not escaped in the generated form XML"
)
REMEDIATION = (
    "Upgrade to Joomla 5.4.11, 6.2.1, or newer. Joomla 4.x has no fixed release; "
    "migrate to a supported branch."
)


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return Status.INCONCLUSIVE
    if parse_version_required("4.0.0") <= parsed < parse_version_required("5.4.11"):
        return Status.LIKELY_VULNERABLE
    if parse_version_required("6.0.0") <= parsed < parse_version_required("6.2.1"):
        return Status.LIKELY_VULNERABLE
    if parsed >= parse_version_required("4.0.0"):
        return Status.PATCHED
    return Status.NOT_AFFECTED


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
    del target_url, timeout, proxy, exploit_mode, aggressive_command, aggressive_args, kwargs
    finding = passive_core_finding(
        cve=CVE_ID,
        name=NAME,
        affected_rule=RULE,
        joomla_version=joomla_version,
        classify=classify_version,
        remediation=REMEDIATION,
    )
    if run_exploit_check:
        finding.detail += (
            " No active proof is included: the advisory names no endpoint or trigger, and "
            "reproduction needs an authenticated custom-field editor plus an article form."
        )
    return finding


def affects_joomla_version(joomla_version: str | None) -> bool:
    return classify_version(joomla_version) in {Status.LIKELY_VULNERABLE, Status.INCONCLUSIVE}


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": "Joomla core com_fields media custom field",
        "affected_rule": RULE,
        "affected_joomla_versions": ["4.0.0-5.4.10", "6.0.0-6.2.0"],
        "exploit_available": False,
        "exploit_modes": [],
        "intrusive": False,
        "vulnerability_type": "Remote Code Execution",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-25",
        "updated": "2026-11-25",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-129393",
            "https://developer.joomla.org/security-centre/1154-20261156-core-rce-through-media-custom-field-parameters.html",
        ],
    }
