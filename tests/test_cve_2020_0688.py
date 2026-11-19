from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.generic import cve_2020_0688


def test_2020_0688_version_boundaries() -> None:
    assert cve_2020_0688.classify_version("14.3.468.2") == "LIKELY_VULNERABLE"
    assert cve_2020_0688.classify_version("14.3.468.3") == "PATCHED"
    assert cve_2020_0688.classify_version("15.0.1497.1") == "LIKELY_VULNERABLE"
    assert cve_2020_0688.classify_version("15.0.1497.2") == "PATCHED"
    assert cve_2020_0688.classify_version("15.1.1713.4") == "LIKELY_VULNERABLE"
    assert cve_2020_0688.classify_version("15.1.1713.5") == "PATCHED"
    assert cve_2020_0688.classify_version("15.2.792.2") == "LIKELY_VULNERABLE"
    assert cve_2020_0688.classify_version("15.2.792.3") == "PATCHED"
    assert cve_2020_0688.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_2020_0688_vulnerable_surface() -> None:
    surface = {
        "path": "/owa/auth/logon.aspx",
        "status": 200,
        "version": "15.2.792.2",
        "surface": True,
    }
    with patch.object(cve_2020_0688, "_owa_surface", return_value=surface):
        result = cve_2020_0688.check("https://exchange.test")
    assert result.status == "LIKELY_VULNERABLE"
    assert result.confidence == "HIGH"
    assert result.exploit_available is False
    assert result.exploit_ran is False


def test_2020_0688_patched_surface() -> None:
    surface = {
        "path": "/owa/",
        "status": 200,
        "version": "15.2.792.3",
        "surface": True,
    }
    with patch.object(cve_2020_0688, "_owa_surface", return_value=surface):
        result = cve_2020_0688.check("https://exchange.test")
    assert result.status == "PATCHED"


def test_2020_0688_no_surface() -> None:
    with patch.object(cve_2020_0688, "_owa_surface", return_value=None):
        result = cve_2020_0688.check("https://not-exchange.test")
    assert result.status == "NOT_DETECTED"


def test_2020_0688_metadata_is_passive() -> None:
    metadata = cve_2020_0688.metadata()
    assert metadata["exploit_modes"] == []
    assert metadata["intrusive"] is False
