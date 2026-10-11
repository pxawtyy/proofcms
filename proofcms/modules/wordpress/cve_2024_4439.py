from __future__ import annotations

from typing import Any

from .core_advisory import metadata as advisory_metadata
from .core_advisory import passive_result

CVE_ID = "CVE-2024-4439"
NAME = "WordPress core unauthenticated stored XSS in Avatar block"
COMPONENT = "WordPress core"
AFFECTED_RULE = "WordPress 6.0.0 through the branch-specific releases fixed in 6.0.8-6.5.2"
FIXED_BY_BRANCH = {"6.0": "6.0.8", "6.1": "6.1.6", "6.2": "6.2.5", "6.3": "6.3.4", "6.4": "6.4.4", "6.5": "6.5.2"}
POC = (
    'With the affected Avatar block settings enabled, use the author/name payload '
    '" autofocus onfocus=alert`XSS`// and render the block. The PoC is documented '
    'by WPScan and is not sent by this module.'
)


def classify_version(version: str | None) -> str:
    from .core_advisory import classify_version as _classify
    return _classify(version, FIXED_BY_BRANCH)


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False, **kwargs: Any):
    return passive_result(
        advisory_id=CVE_ID, name=NAME, affected_rule=AFFECTED_RULE, fixed_by_branch=FIXED_BY_BRANCH,
        wordpress_version=cms_version, cvss="8.3", vulnerability_type="Cross-Site Scripting (XSS)",
        description="The Avatar block can emit an unsanitized author name in an attribute context.",
        remediation="Upgrade WordPress to the fixed branch release (6.0.8, 6.1.6, 6.2.5, 6.3.4, 6.4.4, or 6.5.2+) and review stored author/comment content.",
        references=["https://wpscan.com/vulnerability/1a5c5df1-57ee-4190-a336-b0266962078f/", "https://nvd.nist.gov/vuln/detail/CVE-2024-4439", "https://wordpress.org/news/2024/04/wordpress-6-5-2-maintenance-and-security-release/"],
        poc=POC,
    )


def metadata() -> dict[str, Any]:
    return advisory_metadata(advisory_id=CVE_ID, name=NAME, affected_rule=AFFECTED_RULE, fixed_by_branch=FIXED_BY_BRANCH, cvss="8.3", vulnerability_type="Cross-Site Scripting (XSS)", references=["https://wpscan.com/vulnerability/1a5c5df1-57ee-4190-a336-b0266962078f/", "https://nvd.nist.gov/vuln/detail/CVE-2024-4439", "https://wordpress.org/news/2024/04/wordpress-6-5-2-maintenance-and-security-release/"], poc=POC)
