from __future__ import annotations

from unittest.mock import patch

from proofcms.core.models import Finding
from proofcms.modules.joomla import cve_2026_78077


def test_helix_78077_version_boundaries():
    assert cve_2026_78077.classify_version("2.2.4") == "LIKELY_VULNERABLE"
    assert cve_2026_78077.classify_version("2.2.9") == "LIKELY_VULNERABLE"
    assert cve_2026_78077.classify_version("2.2.10") == "NOT_AFFECTED"
    assert cve_2026_78077.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_helix_78077_reuses_mega_menu_probe():
    shared = Finding(cve="CVE-2026-57829", name="shared", status="VULNERABLE", confidence="CONFIRMED", component="Helix Ultimate", affected_rule="old", detail="marker rendered")
    with patch.object(cve_2026_78077.mega_menu, "run_aggressive_probe", return_value=shared):
        result = cve_2026_78077.run_aggressive_probe("https://target.test")
    assert result.cve == "CVE-2026-78077"
    assert result.status == "VULNERABLE"
    assert "Mega Menu" in result.detail


def test_helix_78077_passive_reports_vulnerable_version():
    result = cve_2026_78077.passive_result({"helixultimate": {"found": True, "version": "2.2.4"}})
    assert result.status == "LIKELY_VULNERABLE"


def test_helix_78077_passive_ignores_absent_component():
    result = cve_2026_78077.passive_result({"helixultimate": {"found": False}})
    assert result.status == "NOT_DETECTED"
