from __future__ import annotations

from typing import Any

from ...core.http import HttpClient, normalize_url
from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_required, parse_version_safe
from .nginx_memory import runtime_finding

CVE_ID = "CVE-2026-42055"
NAME = "NGINX proxy-v2 and gRPC module heap buffer overflow"
RULE = "NGINX 1.13.10-1.30.2 stable and 1.31.0-1.31.1 mainline with proxy-v2 or gRPC configuration"
VULN_TYPE = "Memory Corruption"

# NGX_HTTP_V2_MAX_FIELD = 127 + (1 << (NGX_HTTP_V2_INT_OCTETS - 1) * 7) - 1,
# with NGX_HTTP_V2_INT_OCTETS = 4, i.e. 2,097,278 bytes.
MAX_FIELD = 2_097_278
SMALL_SIZE = 1_024
BELOW_SIZE = 2_000_000
ABOVE_SIZE = MAX_FIELD + 100_000
BLOCKED_STATUSES = {403, 429}


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


def _status(client: HttpClient, url: str, size: int, timeout: int) -> int:
    response = client.get(url, headers={"X-ProofCMS-Length": "A" * size}, timeout=timeout)
    return int(response.get("status", 0))


def run_aggressive_probe(
    target_url: str,
    timeout: int = 30,
    proxy: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    aggressive_command: str | None = None,
) -> Finding:
    """Status differential around the HTTP/2 field-length limit.

    Compares a small header, a header below the limit and a header above the
    limit. The affected build accepts the above-limit field (no rejection);
    the fixed build rejects it. A below-limit control distinguishes a genuine
    length check from a generic large-request block.

    This sends a multi-megabyte header and may restart a worker process on some
    affected builds. Run it only in an isolated lab with explicit acknowledgement.
    """
    base = normalize_url(target_url)
    evidence: dict[str, Any] = {
        "field_limit": MAX_FIELD,
        "small_size": SMALL_SIZE,
        "below_size": BELOW_SIZE,
        "above_size": ABOVE_SIZE,
        "acknowledgement": "isolated lab only; a worker process may restart",
    }
    client = HttpClient(base_url=base, timeout=timeout, proxy=proxy)
    try:
        small = _status(client, base, SMALL_SIZE, timeout)
        below = _status(client, base, BELOW_SIZE, timeout)
        above = _status(client, base, ABOVE_SIZE, timeout)
    except Exception as exc:  # noqa: BLE001 - report transport failure, do not crash the scan
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_CONFIRMED,
            confidence=Confidence.MEDIUM,
            component="NGINX runtime",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=base,
            evidence={**evidence, "transport_error": str(exc)[:200]},
            detail="The length-limit status probe could not complete.",
            action="Upgrade NGINX and review proxy-v2 / gRPC configuration.",
            vulnerability_type=VULN_TYPE,
        )

    evidence.update(
        {
            "small_status": small,
            "below_status": below,
            "above_status": above,
            "above_differs": above != below,
        }
    )
    detail_common = (
        "The probe compared HTTP status codes for small, below-limit and above-limit "
        "header fields; no file was written and no command was executed."
    )
    if small in BLOCKED_STATUSES or below in BLOCKED_STATUSES:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_CONFIRMED,
            confidence=Confidence.MEDIUM,
            component="NGINX runtime",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=base,
            evidence=evidence,
            detail="Requests were blocked before the length-limit comparison could be made. " + detail_common,
            action="Upgrade NGINX and review proxy-v2 / gRPC configuration.",
            vulnerability_type=VULN_TYPE,
        )

    if small == below and above == below:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.VULNERABLE,
            confidence=Confidence.CONFIRMED,
            component="NGINX runtime",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=base,
            evidence=evidence,
            detail=(
                "An above-limit HTTP/2 header field was accepted without the rejection "
                "returned by the fixed build, while the below-limit control behaved like "
                "the small baseline. " + detail_common
            ),
            action="Upgrade NGINX and review proxy-v2 / gRPC configuration.",
            vulnerability_type=VULN_TYPE,
        )

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=Status.NOT_CONFIRMED,
        confidence=Confidence.MEDIUM,
        component="NGINX runtime",
        affected_rule=RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=base,
        evidence=evidence,
        detail=(
            "The above-limit field was rejected or behaved differently from the controls, "
            "consistent with the fixed length check. " + detail_common
        ),
        action="Upgrade NGINX and review proxy-v2 / gRPC configuration.",
        vulnerability_type=VULN_TYPE,
    )


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    nginx_runtime: dict[str, Any] | None = None,
    aggressive_command: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Finding:
    result = runtime_finding(
        cve=CVE_ID,
        name=NAME,
        rule=RULE,
        nginx_runtime=nginx_runtime,
        classify=classify_version,
        required_feature="proxy-v2 or gRPC upstream with invalid-header tolerance",
        remediation="Upgrade to NGINX 1.30.3, 1.31.2, or a newer supported release and review proxy-v2 / gRPC configuration.",
        vulnerability_type=VULN_TYPE,
    )
    if not run_exploit_check:
        return result
    if exploit_mode != "aggressive":
        result.detail += " This module supports only the isolated-lab aggressive length-limit probe."
        return result
    if result.status not in {Status.LIKELY_VULNERABLE, Status.DETECTED_VERSION_UNKNOWN}:
        result.detail += " Active check skipped because the detected runtime is not affected."
        return result
    probe = run_aggressive_probe(
        target_url,
        timeout=timeout,
        proxy=proxy,
        aggressive_args=aggressive_args,
        aggressive_command=aggressive_command,
    )
    probe.component_version = (nginx_runtime or {}).get("version")
    return probe


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "generic",
        "name": NAME,
        "component": "NGINX runtime",
        "affected_rule": RULE,
        "affected_versions": [">=1.13.10,<1.30.3", ">=1.31.0,<1.31.2"],
        "exploit_available": True,
        "exploit_modes": ["aggressive"],
        "intrusive": True,
        "vulnerability_type": VULN_TYPE,
        "references": ["https://nginx.org/en/security_advisories.html"],
    }
