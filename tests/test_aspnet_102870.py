from proofcms.modules.generic import cve_2026_102870


def test_102870_version_boundaries():
    assert cve_2026_102870.classify_version("10.0.12") == "LIKELY_VULNERABLE"
    assert cve_2026_102870.classify_version("10.0.13") == "PATCHED"
    assert cve_2026_102870.classify_version("11.0.0-preview.1") == "LIKELY_VULNERABLE"
    assert cve_2026_102870.classify_version(None) == "INCONCLUSIVE"


def test_102870_is_passive():
    result = cve_2026_102870.check(
        "https://fixture.test",
        cms_version="10.0.12",
        run_exploit_check=True,
    )
    assert result.status == "LIKELY_VULNERABLE"
    assert result.exploit_available is False
    assert result.exploit_ran is False
    assert "passive-only" in result.detail


def test_102870_metadata_is_passive():
    metadata = cve_2026_102870.metadata()
    assert metadata["exploit_modes"] == []
    assert metadata["intrusive"] is False
    assert metadata["required_detectors"] == ["aspnet"]
