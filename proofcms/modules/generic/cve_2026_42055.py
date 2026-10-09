from __future__ import annotations

from typing import Any

from ...core.models import Status
from ...core.versions import parse_version_required, parse_version_safe
from .nginx_memory import passive_only, runtime_finding

CVE_ID = "CVE-2026-42055"
NAME = "NGINX proxy-v2 and gRPC module heap buffer overflow"
RULE = "NGINX 1.13.10-1.30.2 stable and 1.31.0-1.31.1 mainline with proxy-v2 or gRPC configuration"


def classify_version(version: str | None) -> str:
    value = parse_version_safe(version)
    if value is None:
        return Status.DETECTED_VERSION_UNKNOWN
    if value < parse_version_required("1.13.10"):
        return Status.NOT_AFFECTED
    if parse_version_required("1.30.3") <= value < parse_version_required("1.31.0"):
        return Status.PATCHED
    if value >= parse_version_required("1.31.2"):
        return Status.PATCHED
    return Status.LIKELY_VULNERABLE


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False,
          nginx_runtime: dict[str, Any] | None = None, **kwargs: Any):
    result = runtime_finding(
        cve=CVE_ID, name=NAME, rule=RULE, nginx_runtime=nginx_runtime, classify=classify_version,
        required_feature="ngx_http_proxy_v2_module or ngx_http_grpc_module on an exercised upstream path",
        remediation="Upgrade to NGINX 1.30.3, 1.31.2, or newer and review proxy-v2/gRPC locations.",
    )
    return passive_only(result, run_exploit_check)


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID, "cms": "generic", "name": NAME, "component": "NGINX runtime",
        "affected_rule": RULE,
        "affected_versions": [">=1.13.10,<1.30.3", ">=1.31.0,<1.31.2"],
        "exploit_available": False, "exploit_modes": [], "intrusive": True,
        "vulnerability_type": "Memory Corruption",
        "references": ["https://nginx.org/en/security_advisories.html"],
    }
