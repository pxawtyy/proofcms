from __future__ import annotations

from typing import Any

from ...core.models import Status
from ...core.versions import parse_version_required, parse_version_safe
from .nginx_memory import passive_only, runtime_finding

CVE_ID = "CVE-2026-121810"
NAME = "NGINX HTTP/3 QUIC connection reuse use-after-free"
RULE = (
    "NGINX 1.25.0-1.31.8 with HTTP/3 forwarding requests to an upstream; "
    "fixed in 1.31.9"
)


def classify_version(version: str | None) -> str:
    value = parse_version_safe(version)
    if value is None:
        return Status.DETECTED_VERSION_UNKNOWN
    if value < parse_version_required("1.25.0"):
        return Status.NOT_AFFECTED
    if value >= parse_version_required("1.31.9"):
        return Status.PATCHED
    return Status.LIKELY_VULNERABLE


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
        required_feature="ngx_http_v3_module with a listener negotiating HTTP/3 and upstream forwarding",
        remediation=(
            "Upgrade to NGINX 1.31.9 or a newer supported release; until then remove QUIC listeners, "
            "set http3 off; and clear Alt-Svc, and give worker_connections ample headroom."
        ),
        require_http3=True,
    )
    return passive_only(
        result,
        run_exploit_check,
        reason="an active proof needs upstream forwarding configuration that is not visible externally",
    )


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "generic",
        "name": NAME,
        "component": "NGINX runtime",
        "affected_rule": RULE,
        "affected_versions": [">=1.25.0,<1.31.9"],
        "exploit_available": False,
        "exploit_modes": [],
        "intrusive": True,
        "vulnerability_type": "Memory Corruption",
        "references": [
            "https://nginx.org/en/security_advisories.html",
            "https://xint.io/blog/nginx2root-remote-code-execution",
        ],
    }
