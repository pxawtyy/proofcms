from __future__ import annotations

from typing import Any

from .core_advisory import classify_version as _classify
from .core_advisory import metadata as advisory_metadata
from .core_advisory import passive_result

CVE_ID = "CVE-2026-64638"
NAME = "WordPress core pre-auth reflected XSS on login screen"
COMPONENT = "WordPress core"
AFFECTED_RULE = "WordPress 4.7.0 through branch-specific releases fixed in 4.7.34-7.0.3"
FIXED_BY_BRANCH = {"4.7": "4.7.34", "4.8": "4.8.29", "4.9": "4.9.30", "5.0": "5.0.26", "5.1": "5.1.23", "5.2": "5.2.25", "5.3": "5.3.22", "5.4": "5.4.20", "5.5": "5.5.19", "5.6": "5.6.18", "5.7": "5.7.16", "5.8": "5.8.14", "5.9": "5.9.14", "6.0": "6.0.13", "6.1": "6.1.11", "6.2": "6.2.10", "6.3": "6.3.9", "6.4": "6.4.9", "6.5": "6.5.9", "6.6": "6.6.6", "6.7": "6.7.6", "6.8": "6.8.7", "6.9": "6.9.6", "7.0": "7.0.3"}


def classify_version(version: str | None) -> str:
    return _classify(version, FIXED_BY_BRANCH)


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False, **kwargs: Any):
    return passive_result(
        advisory_id=CVE_ID, name=NAME, affected_rule=AFFECTED_RULE, fixed_by_branch=FIXED_BY_BRANCH,
        wordpress_version=cms_version, cvss="8.9", vulnerability_type="Cross-Site Scripting (XSS)",
        description="The login screen can reflect attacker-controlled error content without adequate escaping.",
        remediation="Upgrade WordPress to the fixed branch release (7.0.3 or the corresponding backport) and review login-page protections.",
        references=["https://wpscan.com/vulnerability/4594236f-c7ad-41d6-945b-170eaabe2b75/", "https://nvd.nist.gov/vuln/detail/CVE-2026-64638", "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-52p2-r8wf-jcrf"],
    )


def metadata() -> dict[str, Any]:
    return advisory_metadata(advisory_id=CVE_ID, name=NAME, affected_rule=AFFECTED_RULE, fixed_by_branch=FIXED_BY_BRANCH, cvss="8.9", vulnerability_type="Cross-Site Scripting (XSS)", references=["https://wpscan.com/vulnerability/4594236f-c7ad-41d6-945b-170eaabe2b75/", "https://nvd.nist.gov/vuln/detail/CVE-2026-64638", "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-52p2-r8wf-jcrf"])
