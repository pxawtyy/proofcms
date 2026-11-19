from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.generic import cve_2026_114146


def test_114146_version_boundaries() -> None:
    assert cve_2026_114146.classify_version("1.2.0") == "LIKELY_VULNERABLE"
    assert cve_2026_114146.classify_version("1.2.13") == "LIKELY_VULNERABLE"
    assert cve_2026_114146.classify_version("1.2.14") == "PATCHED"
    assert cve_2026_114146.classify_version("1.1.0") == "NOT_AFFECTED"
    assert cve_2026_114146.classify_version("8.0.21") == "DETECTED_VERSION_UNKNOWN"
    assert cve_2026_114146.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_114146_vulnerable_surface() -> None:
    surface = {
        "path": "/hub/negotiate?negotiateVersion=1",
        "status": 200,
        "connection_id": True,
        "transports": 2,
    }
    with patch.object(cve_2026_114146, "_signalr_surface", return_value=surface):
        result = cve_2026_114146.check("https://app.test", cms_version="1.2.13")
    assert result.status == "LIKELY_VULNERABLE"
    assert result.confidence == "HIGH"
    assert result.exploit_available is False
    assert result.exploit_ran is False


def test_114146_patched() -> None:
    surface = {
        "path": "/hub/negotiate?negotiateVersion=1",
        "status": 200,
        "connection_id": True,
        "transports": 2,
    }
    with patch.object(cve_2026_114146, "_signalr_surface", return_value=surface):
        result = cve_2026_114146.check("https://app.test", cms_version="1.2.14")
    assert result.status == "PATCHED"


def test_114146_no_surface_no_version() -> None:
    with patch.object(cve_2026_114146, "_signalr_surface", return_value=None):
        result = cve_2026_114146.check("https://app.test")
    assert result.status == "NOT_DETECTED"


def test_114146_metadata_is_passive() -> None:
    metadata = cve_2026_114146.metadata()
    assert metadata["exploit_modes"] == []
    assert metadata["intrusive"] is False
