"""CMS-independent web component vulnerability modules."""

AVAILABLE_CVES: dict[str, str] = {
    "CVE-2018-9206": "proofcms.modules.generic.cve_2018_9206",
    "CVE-2021-23394": "proofcms.modules.generic.cve_2021_23394",
    "CVE-2026-81891": "proofcms.modules.generic.cve_2026_81891",
}

__all__ = ["AVAILABLE_CVES"]
