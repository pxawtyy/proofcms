"""WordPress vulnerability module registry."""

from . import (
    cve_2020_35489,
    cve_2023_28121,
    cve_2026_6692,
    cve_2026_18781,
    cve_2026_32475,
    cve_2026_60137,
    cve_2026_63030,
    cve_2026_87902,
)

AVAILABLE_CVES: dict[str, str] = {
    "CVE-2020-35489": "proofcms.modules.wordpress.cve_2020_35489",
    "CVE-2023-28121": "proofcms.modules.wordpress.cve_2023_28121",
    "CVE-2026-6692": "proofcms.modules.wordpress.cve_2026_6692",
    "CVE-2026-18781": "proofcms.modules.wordpress.cve_2026_18781",
    "CVE-2026-32475": "proofcms.modules.wordpress.cve_2026_32475",
    "CVE-2026-60137": "proofcms.modules.wordpress.cve_2026_60137",
    "CVE-2026-63030": "proofcms.modules.wordpress.cve_2026_63030",
    "CVE-2026-87902": "proofcms.modules.wordpress.cve_2026_87902",
}

__all__ = [
    "AVAILABLE_CVES",
    "cve_2020_35489",
    "cve_2023_28121",
    "cve_2026_6692",
    "cve_2026_18781",
    "cve_2026_32475",
    "cve_2026_60137",
    "cve_2026_63030",
    "cve_2026_87902",
]
