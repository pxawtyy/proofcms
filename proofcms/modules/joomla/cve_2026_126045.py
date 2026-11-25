from __future__ import annotations

import urllib.parse
from typing import Any

from ...core.args import aggressive_value
from ...core.http import (
    HttpClient,
    is_transport_error,
    normalize_url,
    transport_error_detail,
)
from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_required, parse_version_safe
from .advisory import passive_core_finding

CVE_ID = "CVE-2026-126045"
NAME = "Joomla core local file inclusion through the language parameter"
RULE = (
    "Joomla 1.6.0-5.4.10 and 6.0.0-6.2.0; the language request value is used "
    "to build a language-file include path without tag validation"
)
REMEDIATION = (
    "Upgrade to Joomla 5.4.11, 6.2.1, or newer. Joomla 1.6-4.x has no fixed "
    "release; migrate to a supported branch."
)


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return Status.INCONCLUSIVE
    if parse_version_required("1.6.0") <= parsed < parse_version_required("5.4.11"):
        return Status.LIKELY_VULNERABLE
    if parse_version_required("6.0.0") <= parsed < parse_version_required("6.2.1"):
        return Status.LIKELY_VULNERABLE
    if parsed >= parse_version_required("1.6.0"):
        return Status.PATCHED
    return Status.NOT_AFFECTED


def run_safe_probe(
    target_url: str,
    language: str,
    marker: str,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Request a lab-seeded language directory through the request parameter."""
    base = normalize_url(target_url).rstrip("/")
    endpoint = f"{base}/?language={urllib.parse.quote(language, safe='/')}"
    client = HttpClient(base_url=base, timeout=timeout, proxy=proxy)
    response = client.get(f"/?language={urllib.parse.quote(language, safe='/')}", timeout=timeout)
    if is_transport_error(response):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.ERROR,
            confidence=Confidence.LOW,
            component="Joomla core language handling",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=endpoint,
            detail=f"The language probe failed in transit ({transport_error_detail(response)}).",
            action="Retry when the target is reachable.",
            vulnerability_type="Local File Inclusion",
        )
    body = str(response.get("body") or "")
    evidence = {
        "endpoint": endpoint,
        "language": language,
        "marker": marker,
        "status": response.get("status", 0),
        "body_len": len(body),
        "marker_found": marker in body,
    }
    if marker in body:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.VULNERABLE,
            confidence=Confidence.CONFIRMED,
            component="Joomla core language handling",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=endpoint,
            evidence=evidence,
            detail=(
                "The language request value traversed to a lab-seeded directory and the "
                "marker from its joomla.ini was rendered in the response. The include path "
                "is controlled by the request parameter."
            ),
            action="Upgrade to Joomla 5.4.11, 6.2.1, or newer; audit webserver access logs for traversal language values.",
            vulnerability_type="Local File Inclusion",
        )
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=Status.NOT_CONFIRMED,
        confidence=Confidence.HIGH,
        component="Joomla core language handling",
        affected_rule=RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=endpoint,
        evidence=evidence,
        detail=(
            "The traversal language value was sent, but the marker did not appear. The "
            "release likely rejects non-language-tag values, the languagefilter plugin "
            "overrode the request value, or the marker directory is absent."
        ),
        action="Verify Joomla runs 5.4.11, 6.2.1, or newer.",
        vulnerability_type="Local File Inclusion",
    )


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aggressive_command: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Finding:
    del kwargs
    finding = passive_core_finding(
        cve=CVE_ID,
        name=NAME,
        affected_rule=RULE,
        joomla_version=joomla_version,
        classify=classify_version,
        remediation=REMEDIATION,
    )
    finding.exploit_available = True
    finding.vulnerability_type = "Local File Inclusion"
    if not run_exploit_check:
        return finding
    if exploit_mode != "safe":
        finding.detail += " This module supports only the safe lab-marker probe."
        return finding
    if finding.status not in {Status.LIKELY_VULNERABLE, Status.INCONCLUSIVE}:
        finding.detail += " Safe proof skipped because the detected release is not affected."
        return finding
    language = aggressive_value(aggressive_args, aggressive_command, "language") or aggressive_value(
        aggressive_args, aggressive_command, "marker_language"
    )
    marker = aggressive_value(aggressive_args, aggressive_command, "marker") or aggressive_value(
        aggressive_args, aggressive_command, "marker_value"
    )
    if not language or not marker:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.BLOCKED_EXTERNAL,
            confidence=Confidence.MEDIUM,
            component="Joomla core language handling",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=False,
            proof_url=f"{normalize_url(target_url).rstrip('/')}/?language=<traversal>",
            detail=(
                "The safe proof reads a marker from a lab-seeded language directory. Pass "
                "--aggressive-arg language=<traversal> and --aggressive-arg marker=<string> "
                "for the lab fixture. Nothing was sent."
            ),
            action="Re-run with the lab marker path and value.",
            vulnerability_type="Local File Inclusion",
        )
    probe = run_safe_probe(target_url, language, marker, timeout=timeout, proxy=proxy)
    probe.component_version = joomla_version
    return probe


def affects_joomla_version(joomla_version: str | None) -> bool:
    return classify_version(joomla_version) in {Status.LIKELY_VULNERABLE, Status.INCONCLUSIVE}


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": "Joomla core language handling",
        "affected_rule": RULE,
        "affected_joomla_versions": ["1.6.0-5.4.10", "6.0.0-6.2.0"],
        "exploit_available": True,
        "exploit_modes": ["safe"],
        "intrusive": False,
        "vulnerability_type": "Local File Inclusion",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-25",
        "updated": "2026-11-25",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-126045",
            "https://developer.joomla.org/security-centre/1110-20261112-core-local-file-inclusion-through-language-parameter.html",
        ],
    }
