from __future__ import annotations

import re
import time
from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-77994"
NAME = "Page Builder CK frontend loadStyles second-order SQL injection"
COMPONENT = "Page Builder CK"
AFFECTED_RULE = "Page Builder CK 1.0.0 through 3.6.4; fixed in 3.6.5"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe", "aggressive"]
PAGE_PATH = "/index.php?option=com_pagebuilderck&view=page&id={page}"
SLEEP_THRESHOLD = 1.2


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
        detail = f"Detected Page Builder CK {version}, which casts the data-styles list to integers."
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


def run_aggressive_probe(
    target_url: str,
    probe_page: int = 1,
    baseline_page: int = 2,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Time-based proof of the stored ``data-styles`` SQL injection.

    The frontend page model parses the stored page HTML, reads
    ``div.pagebuilderckparams[data-styles]`` and concatenates it raw into
    ``WHERE a.id in ( ... )``. 3.6.5 casts each comma-separated value to int.
    The lab fixture stores a page with ``1) AND SLEEP(2)-- -``; the baseline
    page stores ``1``. The probe is read-only (SELECT with SLEEP).
    """
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    baseline_url = f"{base}{PAGE_PATH.format(page=baseline_page)}"
    probe_url = f"{base}{PAGE_PATH.format(page=probe_page)}"
    baseline, baseline_time = _timed_get(client, baseline_url, timeout)
    if is_transport_error(baseline):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=baseline_url, detail=f"The baseline page could not be reached ({transport_error_detail(baseline)}).", action="Retry when the target is reachable.")
    probe, probe_time = _timed_get(client, probe_url, timeout)
    if is_transport_error(probe):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=probe_url, detail=f"The probe page could not be reached ({transport_error_detail(probe)}).", action="Retry when the target is reachable.")

    delta = probe_time - baseline_time
    evidence = {
        "baseline_page": baseline_page,
        "baseline_url": baseline_url,
        "baseline_status": baseline.get("status"),
        "baseline_seconds": round(baseline_time, 3),
        "probe_page": probe_page,
        "probe_url": probe_url,
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
                "The stored page's data-styles value reached the frontend loadStyles() query: the probe page "
                f"added {delta:.2f}s over the benign baseline (threshold {SLEEP_THRESHOLD}s)."
            ),
            action="Upgrade Page Builder CK to 3.6.5 or newer and review stored pages for injected data-styles values.",
        )
    if probe.get("status") in (403, 404):
        detail = (
            f"The probe page returned HTTP {probe.get('status')} before the frontend model ran; the target may "
            "require an editor session or the page fixture is absent."
        )
    else:
        detail = (
            f"The probe page returned HTTP {probe.get('status')} and added only {delta:.2f}s over the baseline; "
            "the stored data-styles value did not reach the ORDER BY-style sink."
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
        detail=detail,
        action="Upgrade affected Page Builder CK versions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}{PAGE_PATH.format(page=1)}"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The component page could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    if response.get("status") == 200:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="A Page Builder CK page is reachable; the timing payload was not sent in safe mode.", action="Use aggressive mode with the stored page and a benign baseline page on an authorized staging site.")
    return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The component page returned HTTP {response.get('status')}; no proof was attempted.", action="Verify the page route on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because Page Builder CK was not detected as potentially affected."
            return passive
        probe_value = aggressive_value(aggressive_args, aggressive_command, "probe_page")
        baseline_value = aggressive_value(aggressive_args, aggressive_command, "baseline_page")
        result = run_aggressive_probe(
            target_url,
            probe_page=int(probe_value) if probe_value and probe_value.isdigit() else 1,
            baseline_page=int(baseline_value) if baseline_value and baseline_value.isdigit() else 2,
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (page reachability) and aggressive (time-based stored SQLi) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "SQL Injection", "module_version": "1.0.0", "last_reviewed": "2026-11-15", "updated": "2026-11-15", "required_detectors": ["pagebuilderck"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-77994", "https://www.joomlack.fr", "https://mysites.guru/vulnerabilities/CVE-2026-77994"]}
