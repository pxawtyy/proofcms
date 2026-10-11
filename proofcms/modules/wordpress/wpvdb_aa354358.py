from __future__ import annotations

from typing import Any

from .core_advisory import classify_version as _classify
from .core_advisory import metadata as advisory_metadata
from .core_advisory import passive_result

ADVISORY_ID = "WPVDB-aa354358-3a32-4e81-8628-d1aa917b5efa"
CVE_ID = ADVISORY_ID
NAME = "WordPress core unauthenticated stored XSS via comments"
FIXED_BY_BRANCH = {"6.0": "6.0.12", "6.1": "6.1.11", "6.2": "6.2.10", "6.3": "6.3.9", "6.4": "6.4.11", "6.5": "6.5.11", "6.6": "6.6.8", "6.7": "6.7.8", "6.8": "6.8.9", "6.9": "6.9.8", "7.0": "7.0.5", "7.1": "7.1.1"}


def classify_version(version: str | None) -> str:
    return _classify(version, FIXED_BY_BRANCH)


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False, **kwargs: Any):
    return passive_result(advisory_id=ADVISORY_ID, name=NAME, affected_rule="WordPress branches below the WPScan-listed fixes (CVSS 8.8 High)", fixed_by_branch=FIXED_BY_BRANCH, wordpress_version=cms_version, cvss="8.8", vulnerability_type="Cross-Site Scripting (XSS)", description="Malformed comment content can execute against viewers after the comment is approved.", remediation="Upgrade to the branch-specific WordPress security release and review existing approved comments.", references=["https://wpscan.com/vulnerability/aa354358-3a32-4e81-8628-d1aa917b5efa/"])


def metadata() -> dict[str, Any]:
    return advisory_metadata(advisory_id=ADVISORY_ID, name=NAME, affected_rule="WordPress branches below the WPScan-listed fixes (CVSS 8.8 High)", fixed_by_branch=FIXED_BY_BRANCH, cvss="8.8", vulnerability_type="Cross-Site Scripting (XSS)", references=["https://wpscan.com/vulnerability/aa354358-3a32-4e81-8628-d1aa917b5efa/"])
