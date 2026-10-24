from __future__ import annotations

from typing import Any

from ...core.categories import VulnerabilityType
from .php_2026_memory import classify_version as _classify_version
from .php_2026_memory import metadata as build_metadata
from .php_2026_memory import runtime_finding

CVE_ID = "CVE-2026-109619"
NAME = "PHP request shutdown residual-state use-after-free"
RULE = "PHP 8.2 before 8.2.35, 8.3 before 8.3.36, 8.4 before 8.4.27, and 8.5 before 8.5.12; legacy branches require package verification"
TYPE = VulnerabilityType.MEMORY_CORRUPTION


def classify_version(version: str | None) -> str:
    return _classify_version(version)


def check(target_url: str, cms_version: str | None = None, php_runtime: dict[str, Any] | None = None, **kwargs: Any):
    return runtime_finding(
        cve=CVE_ID,
        name=NAME,
        vulnerability_type=TYPE,
        rule=RULE,
        action="Upgrade PHP to the fixed branch release. Do not send crash or heap-manipulation payloads to production; verify EOL vendor backports from package metadata.",
        php_runtime=php_runtime,
    )


def metadata() -> dict[str, Any]:
    return build_metadata(
        cve=CVE_ID,
        name=NAME,
        vulnerability_type=TYPE,
        rule=RULE,
        references=["https://www.php.net/", "https://nvd.nist.gov/vuln/detail/CVE-2026-109619"],
    )
