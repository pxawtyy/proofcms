from __future__ import annotations

from typing import Any

from ...core.models import Status
from ...core.versions import parse_version_required, parse_version_safe
from .nginx_memory import passive_only, runtime_finding

CVE_ID = "CVE-2026-90439"
NAME = "NGINX HTTP/3 buffer overflow"
RULE = "NGINX 1.29.2-1.31.5 when ngx_http_v3_module serves HTTP/3"


def classify_version(version: str | None) -> str:
    value = parse_version_safe(version)
    if value is None:
        return Status.DETECTED_VERSION_UNKNOWN
    if value < parse_version_required("1.29.2"):
        return Status.NOT_AFFECTED
    if value >= parse_version_required("1.31.6"):
        return Status.PATCHED
    if parse_version_required("1.30.5") <= value < parse_version_required("1.31.0"):
        return Status.PATCHED
    return Status.LIKELY_VULNERABLE


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False,
          nginx_runtime: dict[str, Any] | None = None, **kwargs: Any):
    result = runtime_finding(
        cve=CVE_ID, name=NAME, rule=RULE, nginx_runtime=nginx_runtime, classify=classify_version,
        required_feature="ngx_http_v3_module with an externally reachable HTTP/3 listener",
        remediation="Upgrade to NGINX 1.30.5, 1.31.6, or a newer supported release.",
        require_http3=True,
    )
    return passive_only(result, run_exploit_check)


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID, "cms": "generic", "name": NAME, "component": "NGINX runtime",
        "affected_rule": RULE, "affected_versions": [">=1.29.2,<1.30.5", ">=1.31.0,<1.31.6"],
        "exploit_available": False, "exploit_modes": [], "intrusive": True,
        "vulnerability_type": "Memory Corruption",
        "references": ["https://nginx.org/en/security_advisories.html"],
    }
