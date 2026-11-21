from __future__ import annotations

from typing import Any

from ...core.models import Status
from ...core.versions import parse_version_required, parse_version_safe
from .nginx_memory import passive_only, runtime_finding

CVE_ID = "CVE-2026-123633"
NAME = "NGINX HTTP/2 reusable-connection invariant break"
RULE = (
    "NGINX 1.19.7-1.30.6 (stable) and 1.31.0-1.31.8 (mainline) with HTTP/2 enabled; "
    "fixed in 1.30.7 and 1.31.9"
)


def classify_version(version: str | None) -> str:
    value = parse_version_safe(version)
    if value is None:
        return Status.DETECTED_VERSION_UNKNOWN
    if value < parse_version_required("1.19.7"):
        return Status.NOT_AFFECTED
    if value >= parse_version_required("1.31.0"):
        return Status.PATCHED if value >= parse_version_required("1.31.9") else Status.LIKELY_VULNERABLE
    return Status.PATCHED if value >= parse_version_required("1.30.7") else Status.LIKELY_VULNERABLE


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    nginx_runtime: dict[str, Any] | None = None,
    **kwargs: Any,
):
    result = runtime_finding(
        cve=CVE_ID,
        name=NAME,
        rule=RULE,
        nginx_runtime=nginx_runtime,
        classify=classify_version,
        required_feature="ngx_http_v2_module with a listener negotiating HTTP/2 via TLS ALPN",
        remediation=(
            "Upgrade to NGINX 1.30.7, 1.31.9, or a newer supported release; until then disable "
            "HTTP/2 (remove the http2 listen parameter, or set http2 off; on 1.25.1+)."
        ),
        require_http2=True,
    )
    return passive_only(
        result,
        run_exploit_check,
        reason="driving the connection drain against a live worker could crash it",
    )


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "generic",
        "name": NAME,
        "component": "NGINX runtime",
        "affected_rule": RULE,
        "affected_versions": [">=1.19.7,<1.30.7", ">=1.31.0,<1.31.9"],
        "exploit_available": False,
        "exploit_modes": [],
        "intrusive": True,
        "vulnerability_type": "Memory Corruption",
        "references": [
            "https://nginx.org/en/security_advisories.html",
            "https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities",
        ],
    }
