from __future__ import annotations

from typing import Any

from .core_advisory import classify_version as _classify
from .core_advisory import metadata as advisory_metadata
from .core_advisory import passive_result

ADVISORY_ID = "WPVDB-df1ca42d-b835-4ed6-a634-3f62ac020e77"
CVE_ID = ADVISORY_ID
NAME = "WordPress core unauthenticated stored XSS via comment moderation"
FIXED_BY_BRANCH = {"6.0": "6.0.17", "6.1": "6.1.15", "6.2": "6.2.14", "6.3": "6.3.13", "6.4": "6.4.13", "6.5": "6.5.13", "6.6": "6.6.10", "6.7": "6.7.10", "6.8": "6.8.11", "6.9": "6.9.10", "7.0": "7.0.7", "7.1": "7.1.3"}


def classify_version(version: str | None) -> str:
    return _classify(version, FIXED_BY_BRANCH)


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False, **kwargs: Any):
    return passive_result(advisory_id=ADVISORY_ID, name=NAME, affected_rule="WordPress branches below the WPScan-listed fixes (CVSS 8.8 High)", fixed_by_branch=FIXED_BY_BRANCH, wordpress_version=cms_version, cvss="8.8", vulnerability_type="Cross-Site Scripting (XSS)", description="Malformed unauthenticated comments can execute when an administrator moderates them.", remediation="Upgrade to the branch-specific WordPress security release and review pending comments before moderation.", references=["https://wpscan.com/vulnerability/df1ca42d-b835-4ed6-a634-3f62ac020e77/"])


def metadata() -> dict[str, Any]:
    return advisory_metadata(advisory_id=ADVISORY_ID, name=NAME, affected_rule="WordPress branches below the WPScan-listed fixes (CVSS 8.8 High)", fixed_by_branch=FIXED_BY_BRANCH, cvss="8.8", vulnerability_type="Cross-Site Scripting (XSS)", references=["https://wpscan.com/vulnerability/df1ca42d-b835-4ed6-a634-3f62ac020e77/"])
