from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ...core.models import Confidence, Finding, Status


def runtime_finding(
    *,
    cve: str,
    name: str,
    rule: str,
    nginx_runtime: dict[str, Any] | None,
    classify: Callable[[str | None], str],
    required_feature: str,
    remediation: str,
    require_http3: bool = False,
    vulnerability_type: str = "Memory Corruption",
) -> Finding:
    runtime = nginx_runtime or {}
    if not runtime.get("detected"):
        return Finding(
            cve,
            name,
            Status.NOT_DETECTED,
            Confidence.LOW,
            "NGINX runtime",
            affected_rule=rule,
            detail="NGINX was not disclosed by the public Server header or response body.",
            action="Verify the edge server and NGINX build internally if headers are suppressed.",
        )
    version = runtime.get("version")
    status = classify(version)
    server = runtime.get("server") or "nginx"
    if status == Status.DETECTED_VERSION_UNKNOWN:
        detail = (
            f"NGINX was detected ({server}), but its version is hidden. Applicability requires {required_feature}."
        )
        confidence = Confidence.LOW
    elif status == Status.LIKELY_VULNERABLE:
        detail = (
            f"Detected NGINX {version}, which is in the upstream affected range, but the required exposure is not "
            f"confirmed. The check requires {required_feature}; public HTTP responses cannot prove the private configuration."
        )
        confidence = Confidence.MEDIUM
        status = Status.NOT_CONFIRMED
        if require_http3:
            if runtime.get("http3_advertised"):
                status = Status.LIKELY_VULNERABLE
                detail += " The origin endpoint advertises HTTP/3 through Alt-Svc."
                confidence = Confidence.HIGH
            else:
                detail += " Origin HTTP/3 was not advertised, so the vulnerable request path was not established."
    elif status == Status.PATCHED:
        detail = f"Detected NGINX {version}, which is in an upstream fixed release range."
        confidence = Confidence.HIGH
    else:
        detail = f"Detected NGINX {version}, which is outside the upstream affected range."
        confidence = Confidence.HIGH
    if version and server and server.lower() != f"nginx/{version}".lower():
        detail += " Distribution/vendor builds may backport fixes without changing the upstream version number."
    return Finding(
        cve,
        name,
        status,
        confidence,
        "NGINX runtime",
        version,
        rule,
        detail=detail,
        action=remediation,
        evidence={
            "server": server,
            "source": runtime.get("source"),
            "http3_advertised": bool(runtime.get("http3_advertised")),
            "edge_server": runtime.get("edge_server"),
            "edge_http3_advertised": bool(runtime.get("edge_http3_advertised")),
            "required_feature": required_feature,
        },
        vulnerability_type=vulnerability_type,
    )


def passive_only(
    result: Finding,
    run_exploit_check: bool,
    reason: str = "triggering this memory-safety flaw could crash a worker",
) -> Finding:
    if run_exploit_check:
        result.detail += f" No active proof was sent because {reason}."
    return result
