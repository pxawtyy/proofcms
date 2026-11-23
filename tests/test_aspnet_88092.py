from proofcms.modules.generic import cve_2026_88092


def test_88092_version_boundaries():
    assert cve_2026_88092.classify_version("8.0.31") == "LIKELY_VULNERABLE"
    assert cve_2026_88092.classify_version("8.0.32") == "PATCHED"
    assert cve_2026_88092.classify_version("9.0.20") == "LIKELY_VULNERABLE"
    assert cve_2026_88092.classify_version("9.0.21") == "PATCHED"
    assert cve_2026_88092.classify_version("10.0.12") == "LIKELY_VULNERABLE"
    assert cve_2026_88092.classify_version("10.0.13") == "PATCHED"
    assert cve_2026_88092.classify_version("11.0.0-rc.1") == "LIKELY_VULNERABLE"
    assert cve_2026_88092.classify_version("11.0.0-rc.2") == "PATCHED"
    assert cve_2026_88092.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_88092_requires_aggressive_mode():
    result = cve_2026_88092.check(
        "https://fixture.test",
        run_exploit_check=True,
        aspnet_runtime={"detected": True, "version": "8.0.31"},
    )
    assert result.status == "LIKELY_VULNERABLE"
    assert result.exploit_ran is False
    assert "isolated-lab aggressive" in result.detail


def test_88092_ignores_core_cms_version_and_requires_aspnet():
    result = cve_2026_88092.check(
        "https://fixture.test",
        cms_version="6.7.0",
        run_exploit_check=True,
    )
    assert result.status == "NOT_DETECTED"
    assert result.component_version is None


def test_88092_metadata_is_aggressive():
    metadata = cve_2026_88092.metadata()
    assert metadata["exploit_modes"] == ["aggressive"]
    assert metadata["intrusive"] is True


def test_88092_aborted_connection_differential():
    from unittest.mock import patch

    def counter(url, timeout):
        return 1 if url.endswith("/hits") else None

    def post(url, host_header, body, timeout):
        return None

    with patch.object(cve_2026_88092, "_counter", side_effect=[1, 1, 1, 2]), patch.object(
        cve_2026_88092, "_aborted_post", side_effect=post
    ), patch.object(cve_2026_88092.time, "sleep"):
        result = cve_2026_88092.run_aggressive_probe("http://fixture.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["trigger_delta"] == 1

    with patch.object(cve_2026_88092, "_counter", side_effect=[0, 0, 0, 0]), patch.object(
        cve_2026_88092, "_aborted_post", side_effect=post
    ), patch.object(cve_2026_88092.time, "sleep"):
        result = cve_2026_88092.run_aggressive_probe("http://fixture.test")
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["trigger_delta"] == 0
