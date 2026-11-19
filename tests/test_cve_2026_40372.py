from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.generic import cve_2026_40372


def test_40372_version_boundaries() -> None:
    assert cve_2026_40372.classify_version("10.0.0") == "LIKELY_VULNERABLE"
    assert cve_2026_40372.classify_version("10.0.6") == "LIKELY_VULNERABLE"
    assert cve_2026_40372.classify_version("10.0.7") == "PATCHED"
    assert cve_2026_40372.classify_version("10.0.8") == "PATCHED"
    assert cve_2026_40372.classify_version("9.0.21") == "NOT_AFFECTED"
    assert cve_2026_40372.classify_version("8.0.32") == "NOT_AFFECTED"
    assert cve_2026_40372.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_40372_vulnerable_with_cookie_surface() -> None:
    surface = {
        "status": 200,
        "surface": True,
        "cookies": [".AspNetCore.Cookies=abc"],
    }
    with patch.object(cve_2026_40372, "_protected_surface", return_value=surface):
        result = cve_2026_40372.check("https://app.test", cms_version="10.0.6")
    assert result.status == "LIKELY_VULNERABLE"
    assert result.confidence == "HIGH"
    assert result.exploit_available is False
    assert result.exploit_ran is False


def test_40372_patched() -> None:
    surface = {"status": 200, "surface": True, "cookies": []}
    with patch.object(cve_2026_40372, "_protected_surface", return_value=surface):
        result = cve_2026_40372.check("https://app.test", cms_version="10.0.7")
    assert result.status == "PATCHED"


def test_40372_no_surface_no_version() -> None:
    with patch.object(cve_2026_40372, "_protected_surface", return_value=None):
        result = cve_2026_40372.check("https://app.test")
    assert result.status == "NOT_DETECTED"


def test_40372_metadata_is_passive() -> None:
    metadata = cve_2026_40372.metadata()
    assert metadata["exploit_modes"] == []
    assert metadata["intrusive"] is False
