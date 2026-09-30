"""Critical web-reachable PHP runtime vulnerability modules."""

AVAILABLE_CVES: dict[str, str] = {
    "CVE-2012-1823": "proofcms.modules.php.cve_2012_1823",
    "CVE-2019-11043": "proofcms.modules.php.cve_2019_11043",
    "CVE-2024-4577": "proofcms.modules.php.cve_2024_4577",
}

__all__ = ["AVAILABLE_CVES"]
