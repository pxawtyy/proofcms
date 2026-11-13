from proofcms.modules.generic import cve_2026_88092


def test_88092_version_boundaries():
    assert cve_2026_88092.classify_version("8.0.31") == "LIKELY_VULNERABLE"
    assert cve_2026_88092.classify_version("8.0.32") == "PATCHED"
    assert cve_2026_88092.classify_version("9.0.20") == "LIKELY_VULNERABLE"
    assert cve_2026_88092.classify_version("9.0.21") == "PATCHED"
    assert cve_2026_88092.classify_version("10.0.12") == "LIKELY_VULNERABLE"
    assert cve_2026_88092.classify_version("10.0.13") == "PATCHED"
    assert cve_2026_88092.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_88092_is_passive():
    result = cve_2026_88092.check(
        "https://fixture.test",
        cms_version="8.0.31",
        run_exploit_check=True,
    )
    assert result.status == "LIKELY_VULNERABLE"
    assert result.exploit_available is False
    assert result.exploit_ran is False
    assert "passive-only" in result.detail


def test_88092_metadata_is_passive():
    metadata = cve_2026_88092.metadata()
    assert metadata["exploit_modes"] == []
    assert metadata["intrusive"] is False
