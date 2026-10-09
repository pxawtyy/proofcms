from __future__ import annotations

from typing import Any

from ...core.models import Status
from ...core.versions import parse_version_required, parse_version_safe
from .nginx_memory import passive_only, runtime_finding

CVE_ID = "CVE-2026-42530"
NAME = "NGINX HTTP/3 use-after-free"
RULE = "NGINX 1.31.0-1.31.1 when ngx_http_v3_module serves HTTP/3"


def classify_version(version: str | None) -> str:
    value = parse_version_safe(version)
    if value is None:
        return Status.DETECTED_VERSION_UNKNOWN
    if parse_version_required("1.31.0") <= value < parse_version_required("1.31.2"):
        return Status.LIKELY_VULNERABLE
    return Status.PATCHED if value >= parse_version_required("1.31.2") else Status.NOT_AFFECTED


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False,
          nginx_runtime: dict[str, Any] | None = None, **kwargs: Any):
    result = runtime_finding(
        cve=CVE_ID, name=NAME, rule=RULE, nginx_runtime=nginx_runtime, classify=classify_version,
        required_feature="ngx_http_v3_module with an externally reachable HTTP/3 listener",
        remediation="Upgrade to NGINX 1.31.2 or newer, or disable HTTP/3 until upgraded.",
        require_http3=True,
    )
    return passive_only(result, run_exploit_check)


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID, "cms": "generic", "name": NAME, "component": "NGINX runtime",
        "affected_rule": RULE, "affected_versions": [">=1.31.0,<1.31.2"],
        "exploit_available": False, "exploit_modes": [], "intrusive": True,
        "vulnerability_type": "Memory Corruption",
        "references": ["https://nginx.org/en/security_advisories.html"],
    }
