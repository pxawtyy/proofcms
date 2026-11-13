"""Critical web-reachable PHP runtime vulnerability modules."""

AVAILABLE_CVES: dict[str, str] = {
    "CVE-2012-1823": "proofcms.modules.php.cve_2012_1823",
    "CVE-2019-11043": "proofcms.modules.php.cve_2019_11043",
    "CVE-2024-2961": "proofcms.modules.php.cve_2024_2961",
    "CVE-2024-4577": "proofcms.modules.php.cve_2024_4577",
    "CVE-2024-8929": "proofcms.modules.php.cve_2024_8929",
    "CVE-2023-3824": "proofcms.modules.php.cve_2023_3824",
    "CVE-2024-8932": "proofcms.modules.php.cve_2024_8932",
    "CVE-2023-3823": "proofcms.modules.php.cve_2023_3823",
    "CVE-2026-109618": "proofcms.modules.php.cve_2026_109618",
    "CVE-2026-109619": "proofcms.modules.php.cve_2026_109619",
}

__all__ = ["AVAILABLE_CVES"]
