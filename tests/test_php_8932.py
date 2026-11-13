from proofcms.modules.php import cve_2024_8932

RUNTIME_32 = {"detected": True, "version": "8.3.13", "source": "/:X-Powered-By", "int_size": 4}


def test_8932_version_boundaries():
    assert cve_2024_8932.classify_version("7.4.33") == "LIKELY_VULNERABLE"
    assert cve_2024_8932.classify_version("8.1.0") == "LIKELY_VULNERABLE"
    assert cve_2024_8932.classify_version("8.1.30") == "LIKELY_VULNERABLE"
    assert cve_2024_8932.classify_version("8.1.31") == "PATCHED"
    assert cve_2024_8932.classify_version("8.2.25") == "LIKELY_VULNERABLE"
    assert cve_2024_8932.classify_version("8.2.26") == "PATCHED"
    assert cve_2024_8932.classify_version("8.3.13") == "LIKELY_VULNERABLE"
    assert cve_2024_8932.classify_version("8.3.14") == "PATCHED"
    assert cve_2024_8932.classify_version("8.4.0") == "PATCHED"
    assert cve_2024_8932.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_8932_32_bit_affected_version_is_version_match_only():
    result = cve_2024_8932.check("https://fixture.test", php_runtime=RUNTIME_32)
    assert result.status == "LIKELY_VULNERABLE"
    assert result.confidence == "MEDIUM"
    assert result.exploit_available is False
    assert "Version match only" in result.detail
    assert "32-bit" in result.detail


def test_8932_64_bit_build_is_not_affected():
    result = cve_2024_8932.check(
        "https://fixture.test",
        php_runtime={"detected": True, "version": "8.3.13", "source": "/:X-Powered-By", "int_size": 8},
    )
    assert result.status == "NOT_AFFECTED"
    assert result.confidence == "HIGH"


def test_8932_patched_version_is_patched():
    result = cve_2024_8932.check(
        "https://fixture.test",
        php_runtime={"detected": True, "version": "8.3.14", "source": "/:X-Powered-By", "int_size": 4},
    )
    assert result.status == "PATCHED"


def test_8932_unknown_version_is_inconclusive():
    result = cve_2024_8932.check(
        "https://fixture.test",
        php_runtime={"detected": True, "version": None, "source": "/:Set-Cookie", "int_size": 4},
    )
    assert result.status == "INCONCLUSIVE"


def test_8932_without_php_is_not_detected():
    result = cve_2024_8932.check("https://fixture.test", php_runtime={"detected": False})
    assert result.status == "NOT_DETECTED"


def test_8932_metadata_is_passive():
    metadata = cve_2024_8932.metadata()
    assert metadata["exploit_modes"] == []
    assert metadata["exploit_available"] is False
    assert metadata["intrusive"] is False
    assert metadata["vulnerability_type"] == "Out-of-bounds Write / Potential RCE"
