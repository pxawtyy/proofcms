from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.generic import cve_2026_70188


def test_70188_version_boundaries() -> None:
    assert cve_2026_70188.classify_version("8.0.31") == "LIKELY_VULNERABLE"
    assert cve_2026_70188.classify_version("8.0.32") == "PATCHED"
    assert cve_2026_70188.classify_version("9.0.20") == "LIKELY_VULNERABLE"
    assert cve_2026_70188.classify_version("9.0.21") == "PATCHED"
    assert cve_2026_70188.classify_version("10.0.12") == "LIKELY_VULNERABLE"
    assert cve_2026_70188.classify_version("10.0.13") == "PATCHED"
    assert cve_2026_70188.classify_version("11.0.0-rc.1") == "LIKELY_VULNERABLE"
    assert cve_2026_70188.classify_version("11.0.0-rc.2") == "PATCHED"
    assert cve_2026_70188.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_70188_safe_probe_vulnerable() -> None:
    probe = {"vulnerable": True, "patched": False}
    with patch.object(cve_2026_70188, "run_safe_probe", return_value=probe):
        result = cve_2026_70188.check(
            "http://127.0.0.1:9260",
            cms_version="8.0.31",
            run_exploit_check=True,
            exploit_mode="safe",
        )
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.exploit_ran is True


def test_70188_safe_probe_patched() -> None:
    probe = {"vulnerable": False, "patched": True}
    with patch.object(cve_2026_70188, "run_safe_probe", return_value=probe):
        result = cve_2026_70188.check(
            "http://127.0.0.1:9261",
            cms_version="8.0.32",
            run_exploit_check=True,
            exploit_mode="safe",
        )
    assert result.status == "PATCHED"


def test_70188_safe_probe_inconclusive() -> None:
    probe = {"inconclusive": True, "reason": "control failed"}
    with patch.object(cve_2026_70188, "run_safe_probe", return_value=probe):
        result = cve_2026_70188.check(
            "http://127.0.0.1:9260",
            cms_version="8.0.31",
            run_exploit_check=True,
            exploit_mode="safe",
        )
    assert result.status == "LIKELY_VULNERABLE"


def test_70188_metadata_is_safe() -> None:
    metadata = cve_2026_70188.metadata()
    assert metadata["exploit_modes"] == ["safe"]
    assert metadata["intrusive"] is False
