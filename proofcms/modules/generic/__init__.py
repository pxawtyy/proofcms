"""CMS-independent web component vulnerability modules."""

AVAILABLE_CVES: dict[str, str] = {
    "CVE-2018-9206": "proofcms.modules.generic.cve_2018_9206",
    "CVE-2021-23394": "proofcms.modules.generic.cve_2021_23394",
    "CVE-2026-9256": "proofcms.modules.generic.cve_2026_9256",
    "CVE-2026-42055": "proofcms.modules.generic.cve_2026_42055",
    "CVE-2026-42530": "proofcms.modules.generic.cve_2026_42530",
    "CVE-2026-42533": "proofcms.modules.generic.cve_2026_42533",
    "CVE-2026-42945": "proofcms.modules.generic.cve_2026_42945",
    "CVE-2026-56434": "proofcms.modules.generic.cve_2026_56434",
    "CVE-2026-60005": "proofcms.modules.generic.cve_2026_60005",
    "CVE-2026-81891": "proofcms.modules.generic.cve_2026_81891",
    "CVE-2026-90439": "proofcms.modules.generic.cve_2026_90439",
}

__all__ = ["AVAILABLE_CVES"]
