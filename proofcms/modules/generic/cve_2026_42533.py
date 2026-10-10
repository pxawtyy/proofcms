from __future__ import annotations

from typing import Any

from ...core.models import Status
from ...core.versions import parse_version_required, parse_version_safe
from .nginx_memory import passive_only, runtime_finding

CVE_ID = "CVE-2026-42533"
NAME = "NGINX map-regex buffer overflow"
RULE = "NGINX 0.9.6-1.31.2 when map uses a vulnerable regular expression"


def classify_version(version: str | None) -> str:
    value = parse_version_safe(version)
    if value is None:
        return Status.DETECTED_VERSION_UNKNOWN
    if value < parse_version_required("0.9.6"):
        return Status.NOT_AFFECTED
    if value >= parse_version_required("1.31.3"):
        return Status.PATCHED
    if parse_version_required("1.30.4") <= value < parse_version_required("1.31.0"):
        return Status.PATCHED
    return Status.LIKELY_VULNERABLE


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False,
          nginx_runtime: dict[str, Any] | None = None, **kwargs: Any):
    result = runtime_finding(
        cve=CVE_ID, name=NAME, rule=RULE, nginx_runtime=nginx_runtime, classify=classify_version,
        required_feature="a map directive containing a vulnerable regular expression",
        remediation="Upgrade to NGINX 1.30.4, 1.31.3, or a newer supported release.",
    )
    return passive_only(result, run_exploit_check)


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID, "cms": "generic", "name": NAME, "component": "NGINX runtime",
        "affected_rule": RULE, "affected_versions": [">=0.9.6,<1.30.4", ">=1.31.0,<1.31.3"],
        "exploit_available": False, "exploit_modes": [], "intrusive": True,
        "vulnerability_type": "Memory Corruption",
        "references": ["https://nginx.org/en/security_advisories.html"],
    }
