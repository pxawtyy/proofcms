from __future__ import annotations

from typing import Any

from ...core.models import Status
from ...core.versions import parse_version_safe
from .common import runtime_finding

CVE_ID = "CVE-2019-11043"
NAME = "PHP-FPM PATH_INFO underflow"
RULE = "PHP-FPM 7.1 before 7.1.33, 7.2 before 7.2.24, and 7.3 before 7.3.11 with vulnerable Nginx fastcgi_split_path_info configuration"
ACTION = (
    "Upgrade PHP, then verify Nginx passes only existing scripts to PHP-FPM and uses a safe PATH_INFO configuration."
)


def classify_version(version: str | None) -> str:
    value = parse_version_safe(version)
    if value is None:
        return Status.DETECTED_VERSION_UNKNOWN
    ranges = (("7.1.0", "7.1.33"), ("7.2.0", "7.2.24"), ("7.3.0", "7.3.11"))
    if any(parse_version_safe(low) <= value < parse_version_safe(high) for low, high in ranges):
        return Status.LIKELY_VULNERABLE
    return Status.PATCHED if value >= parse_version_safe("7.1.33") else Status.NOT_AFFECTED


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
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
        exploit_available=False,
    )
    server = str((php_runtime or {}).get("server") or "").lower()
    if result.status == Status.LIKELY_VULNERABLE and server and "nginx" not in server:
        result.status = Status.NOT_AFFECTED
        result.detail += (
            " The disclosed origin server is not Nginx, so the required deployment pattern was not observed."
        )
    elif result.status == Status.LIKELY_VULNERABLE:
        result.detail += (
            " Nginx/PHP-FPM configuration remains a required precondition; no memory-corruption probe was sent."
        )
    return result


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "php",
        "name": NAME,
        "component": "PHP runtime",
        "affected_rule": RULE,
        "affected_versions": [">=7.1.0,<7.1.33", ">=7.2.0,<7.2.24", ">=7.3.0,<7.3.11"],
        "exploit_available": False,
        "exploit_modes": [],
        "intrusive": False,
        "references": ["https://www.php.net/releases/7_3_11.php", "https://nvd.nist.gov/vuln/detail/CVE-2019-11043"],
    }
