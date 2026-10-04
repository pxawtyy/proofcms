from __future__ import annotations

from .k2_dangerous_extension import check_k2_dangerous_extension

CVE_ID = "CVE-2019-19634"
NAME = "K2 bundled Verot class.upload .pht dangerous-file bypass"


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    plugins: dict | None = None,
    **kwargs,
):
    return check_k2_dangerous_extension(
        cve=CVE_ID,
        name=NAME,
        extension="pht",
        target_url=target_url,
        plugins=plugins,
        run_exploit_check=run_exploit_check,
        exploit_mode=exploit_mode,
        timeout=timeout,
        proxy=proxy,
    )


def metadata() -> dict:
    return {
        "cve": CVE_ID,
        "name": NAME,
        "component": "K2",
        "affected_rule": "K2 releases bundling Verot class.upload before 2.11.20240911",
        "affected_joomla_versions": ["*"],
        "exploit_available": True,
        "exploit_modes": ["aggressive"],
        "intrusive": True,
        "required_detectors": ["k2"],
        "module_version": "1.0.0",
        "last_reviewed": "2026-10-04",
        "updated": "2026-10-04",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2019-19634",
            "https://github.com/getk2/k2/blob/master/CHANGELOG.md",
        ],
    }


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True
