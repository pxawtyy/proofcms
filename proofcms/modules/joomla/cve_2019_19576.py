from __future__ import annotations

from typing import Any

from .k2_dangerous_extension import check_k2_dangerous_extension

CVE_ID = "CVE-2019-19576"
NAME = "K2 bundled Verot class.upload .phar dangerous-file bypass"


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    plugins: dict | None = None,
    aggressive_command: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    **kwargs,
):
    return check_k2_dangerous_extension(
        cve=CVE_ID,
        name=NAME,
        extension="phar",
        fixed_version="2.27",
        target_url=target_url,
        plugins=plugins,
        run_exploit_check=run_exploit_check,
        exploit_mode=exploit_mode,
        timeout=timeout,
        proxy=proxy,
        aggressive_command=aggressive_command,
        aggressive_args=aggressive_args,
    )


def metadata() -> dict:
    return {
        "cve": CVE_ID,
        "name": NAME,
        "component": "K2",
        "affected_rule": "K2 before 2.27 (attachment handler lacks the server-executable extension deny-list)",
        "affected_joomla_versions": ["*"],
        "exploit_available": True,
        "exploit_modes": ["aggressive"],
        "intrusive": True,
        "required_detectors": ["k2"],
        "module_version": "1.1.0",
        "last_reviewed": "2026-11-10",
        "updated": "2026-11-10",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2019-19576",
            "https://github.com/getk2/k2/blob/master/CHANGELOG.md",
        ],
    }


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True
