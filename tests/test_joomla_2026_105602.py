from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_105602


def test_helix_105602_version_boundaries():
    assert cve_2026_105602.classify_version("2.2.10") == "LIKELY_VULNERABLE"
    assert cve_2026_105602.classify_version("2.2.11") == "NOT_AFFECTED"
    assert cve_2026_105602.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_helix_105602_passive_reports_vulnerable_version():
    result = cve_2026_105602.passive_result({"helixultimate": {"found": True, "version": "2.2.10"}})
    assert result.status == "LIKELY_VULNERABLE"


def test_helix_105602_safe_probe_delegates_to_mega_menu():
    shared = cve_2026_105602.Finding(
        cve="CVE-2026-57829",
        name="shared",
        status="BLOCKED_EXTERNAL",
        confidence="MEDIUM",
        component="Helix",
        affected_rule="shared",
    )
    with patch.object(cve_2026_105602.mega_menu, "run_safe_probe", return_value=shared):
        result = cve_2026_105602.run_safe_probe("https://target.test")
    assert result.cve == "CVE-2026-105602"
    assert result.name == cve_2026_105602.NAME
