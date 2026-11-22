from __future__ import annotations

import urllib.parse
from typing import Any

from ...core.args import aggressive_value
from ...core.http import HttpClient, normalize_url
from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_required, parse_version_safe
from .common import runtime_finding

CVE_ID = "CVE-2019-11043"
NAME = "PHP-FPM PATH_INFO underflow"
RULE = "PHP-FPM 7.1 before 7.1.33, 7.2 before 7.2.24, and 7.3 before 7.3.11 with vulnerable Nginx fastcgi_split_path_info configuration"
ACTION = (
    "Upgrade PHP, then verify Nginx passes only existing scripts to PHP-FPM and uses a safe PATH_INFO configuration."
)
VULN_TYPE = "Memory Corruption"

MIN_QSL = 1500
MAX_QSL = 1950
QSL_STEP = 5
MAX_CANDIDATES = 10
BASELINE_PATH_INFO = "/path\ninfo.php"
BREAKING_PATH_INFO = "/PHP\nis_the_shittiest_lang.php"
PROBE_HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "D-Pisos": "8=D",
    "Ebut": "mamku tvoyu",
}


def classify_version(version: str | None) -> str:
    value = parse_version_safe(version)
    if value is None:
        return Status.DETECTED_VERSION_UNKNOWN
    ranges = (("7.1.0", "7.1.33"), ("7.2.0", "7.2.24"), ("7.3.0", "7.3.11"))
    if any(parse_version_required(low) <= value < parse_version_required(high) for low, high in ranges):
        return Status.LIKELY_VULNERABLE
    return Status.PATCHED if value >= parse_version_required("7.1.33") else Status.NOT_AFFECTED


def _request(
    client: HttpClient,
    script_url: str,
    path_info: str,
    qsl: int,
    timeout: int,
) -> int:
    """Issue one status-only probe request with the public detector's framing."""
    escaped = urllib.parse.quote(path_info, safe="/")
    escape_pairs = (len(escaped) - len(path_info)) // 2
    query = "Q" * max(0, qsl - escape_pairs)
    url = f"{script_url}{escaped}?{query}"
    response = client.request(
        url,
        method="GET",
        headers=PROBE_HEADERS,
        timeout=timeout,
        follow_redirects=False,
    )
    return int(response.get("status", 0))


def run_safe_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    aggressive_command: str | None = None,
) -> Finding:
    """Read-only QSL status differential for the PHP-FPM PATH_INFO underflow.

    Sends GET requests with a newline in PATH_INFO and a varying-length query
    string. The affected FPM build changes its HTTP status at a particular
    query-string length; the fixed build does not. No PHP setting is changed,
    no command is executed, and no file is written.
    """
    base = normalize_url(target_url)
    php_path = (
        aggressive_value(aggressive_args, aggressive_command, "php_path", "/index.php")
        or "/index.php"
    )
    script_url = base.rstrip("/") + "/" + php_path.lstrip("/")
    evidence: dict[str, Any] = {
        "script_url": script_url,
        "qsl_range": [MIN_QSL, MAX_QSL],
        "qsl_step": QSL_STEP,
        "read_only": True,
    }

    client = HttpClient(base_url=base, timeout=timeout, proxy=proxy)
    try:
        base_status = _request(client, script_url, BASELINE_PATH_INFO, MIN_QSL, timeout)
        candidates: list[dict[str, int]] = []
        for qsl in range(MIN_QSL, MAX_QSL + 1, QSL_STEP):
            status = _request(client, script_url, BREAKING_PATH_INFO, qsl, timeout)
            if status != base_status:
                candidates.append({"qsl": qsl, "status": status})
    except Exception as exc:  # noqa: BLE001 - report transport failure, do not crash the scan
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_CONFIRMED,
            confidence=Confidence.MEDIUM,
            component="PHP runtime / PHP-FPM",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=script_url,
            evidence={**evidence, "transport_error": str(exc)[:200]},
            detail="The read-only status probe could not complete against the PHP endpoint.",
            action=ACTION,
            vulnerability_type=VULN_TYPE,
        )

    evidence.update(
        {
            "baseline_status": base_status,
            "status_changes": candidates,
            "change_count": len(candidates),
        }
    )
    if 0 < len(candidates) <= MAX_CANDIDATES:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.VULNERABLE,
            confidence=Confidence.CONFIRMED,
            component="PHP runtime / PHP-FPM",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=script_url,
            evidence=evidence,
            detail=(
                "A newline-in-PATH_INFO request changed the HTTP status at specific query-string "
                "lengths, matching the FPM environment underflow. Only status codes were observed; "
                "no PHP setting was changed and no command was executed."
            ),
            action=ACTION,
            vulnerability_type=VULN_TYPE,
        )

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=Status.NOT_CONFIRMED,
        confidence=Confidence.MEDIUM,
        component="PHP runtime / PHP-FPM",
        affected_rule=RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=script_url,
        evidence=evidence,
        detail=(
            "No characteristic status change was observed across the query-string-length sweep "
            "(or too many changes occurred, suggesting an intermediary). The safe probe did not "
            "confirm the FPM underflow."
        ),
        action=ACTION,
        vulnerability_type=VULN_TYPE,
    )


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    php_runtime: dict[str, Any] | None = None,
    aggressive_command: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    **kwargs: Any,
):
    result = runtime_finding(
        cve=CVE_ID,
        name=NAME,
        rule=RULE,
        php_runtime=php_runtime,
        classify=classify_version,
        action=ACTION,
        exploit_available=True,
    )
    result.vulnerability_type = VULN_TYPE
    server = str((php_runtime or {}).get("server") or "").lower()
    if (
        result.status in {Status.LIKELY_VULNERABLE, Status.DETECTED_VERSION_UNKNOWN}
        and server
        and "nginx" not in server
    ):
        result.status = Status.NOT_AFFECTED
        result.confidence = "HIGH"
        result.detail += (
            " The disclosed origin server is not Nginx, so the required deployment pattern was not observed."
        )
    if not run_exploit_check:
        return result
    if exploit_mode != "safe":
        result.detail += " This module supports only the read-only safe QSL status probe."
        return result
    if result.status not in {Status.LIKELY_VULNERABLE, Status.DETECTED_VERSION_UNKNOWN}:
        result.detail += " Safe proof skipped because the detected runtime is not affected."
        return result
    probe = run_safe_probe(
        target_url,
        timeout=timeout,
        proxy=proxy,
        aggressive_args=aggressive_args,
        aggressive_command=aggressive_command,
    )
    probe.component_version = (php_runtime or {}).get("version")
    return probe


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "php",
        "name": NAME,
        "component": "PHP runtime / PHP-FPM",
        "affected_rule": RULE,
        "affected_versions": [">=7.1.0,<7.1.33", ">=7.2.0,<7.2.24", ">=7.3.0,<7.3.11"],
        "exploit_available": True,
        "exploit_modes": ["safe"],
        "intrusive": False,
        "vulnerability_type": VULN_TYPE,
        "references": ["https://www.php.net/releases/7_3_11.php", "https://nvd.nist.gov/vuln/detail/CVE-2019-11043"],
    }
