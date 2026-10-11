from __future__ import annotations

from typing import Any

from .core_advisory import classify_version as _classify
from .core_advisory import metadata as advisory_metadata
from .core_advisory import passive_result

ADVISORY_ID = "WPVDB-5e9804e5-bbd4-4836-a5f0-b4388cc39225"
CVE_ID = ADVISORY_ID
NAME = "WordPress core insecure deserialization / PHP object injection"
FIXED_BY_BRANCH = {"4.1": "4.1.40", "4.2": "4.2.37", "4.3": "4.3.33", "4.4": "4.4.32", "4.5": "4.5.31", "4.6": "4.6.28", "4.7": "4.7.28", "4.8": "4.8.24", "4.9": "4.9.25", "5.0": "5.0.21", "5.1": "5.1.18", "5.2": "5.2.20", "5.3": "5.3.17", "5.4": "5.4.15", "5.5": "5.5.14", "5.6": "5.6.13", "5.7": "5.7.11", "5.8": "5.8.9", "5.9": "5.9.9", "6.0": "6.0.7", "6.1": "6.1.5", "6.2": "6.2.4", "6.3": "6.3.3", "6.4": "6.4.3"}


def classify_version(version: str | None) -> str:
    return _classify(version, FIXED_BY_BRANCH)


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False, **kwargs: Any):
    return passive_result(advisory_id=ADVISORY_ID, name=NAME, affected_rule="WordPress branches below the WPScan-listed fixes (CVSS 8.5 High)", fixed_by_branch=FIXED_BY_BRANCH, wordpress_version=cms_version, cvss="8.5", vulnerability_type="Object Injection", description="Unsanitized options can enable PHP object injection when a compatible gadget chain is present.", remediation="Upgrade to the branch-specific WordPress security release; do not attempt object-injection payloads against production systems.", references=["https://wpscan.com/vulnerability/5e9804e5-bbd4-4836-a5f0-b4388cc39225/", "https://wordpress.org/news/2024/01/wordpress-6-4-3-maintenance-and-security-release/"])


def metadata() -> dict[str, Any]:
    return advisory_metadata(advisory_id=ADVISORY_ID, name=NAME, affected_rule="WordPress branches below the WPScan-listed fixes (CVSS 8.5 High)", fixed_by_branch=FIXED_BY_BRANCH, cvss="8.5", vulnerability_type="Object Injection", references=["https://wpscan.com/vulnerability/5e9804e5-bbd4-4836-a5f0-b4388cc39225/", "https://wordpress.org/news/2024/01/wordpress-6-4-3-maintenance-and-security-release/"])
