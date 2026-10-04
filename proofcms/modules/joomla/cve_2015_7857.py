from __future__ import annotations

import re
import urllib.parse
from typing import Any

from ...core.http import HttpClient, normalize_url
from ...core.versions import parse_version_required, parse_version_safe
from .advisory import passive_core_finding

CVE_ID = "CVE-2015-7857"
NAME = "Joomla core content history SQL injection"
AFFECTED_RULE = "Joomla 3.2.0 through 3.4.4"
SQL_ERROR = re.compile(
    r"(sql syntax|database error|mysqli?_[a-z_]+\(|you have an error in your sql|unknown column|jdatabaseexception)",
    re.IGNORECASE,
)


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

    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    common = {
        "option": "com_contenthistory",
        "view": "history",
        "item_id": "1",
        "type_id": "1",
        "list[ordering]": "editor",
    }
    control_url = f"{base}/index.php?{urllib.parse.urlencode({**common, 'list[select]': '1'})}"
    probe_url = f"{base}/index.php?{urllib.parse.urlencode({**common, 'list[select]': '1,proofcms_missing_column'})}"
    control = client.get(control_url, timeout=timeout)
    probe = client.get(probe_url, timeout=timeout)
    control_error = bool(SQL_ERROR.search(control.get("body", "")))
    probe_error = bool(SQL_ERROR.search(probe.get("body", "")))
    finding.exploit_ran = True
    finding.proof_url = probe_url
    if probe_error and not control_error and probe.get("body_hash") != control.get("body_hash"):
        finding.status = "VULNERABLE"
        finding.confidence = "CONFIRMED"
        finding.detail = (
            "A harmless control request was accepted, while an invalid column injected through list[select] "
            "produced a database-specific error. No database rows were read or modified."
        )
    else:
        finding.status = "NOT_CONFIRMED"
        finding.confidence = "MEDIUM"
        finding.detail = (
            "The content-history SQL differential did not produce a unique database error. "
            f"Control HTTP {control.get('status', 0)}; probe HTTP {probe.get('status', 0)}; "
            f"redirected={probe.get('redirected', False)}."
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
        "module_version": "1.1.0",
        "last_reviewed": "2026-10-03",
        "updated": "2026-10-03",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2015-7857",
            "https://developer.joomla.org/security-centre/628-20151001-core-sql-injection.html",
        ],
    }
