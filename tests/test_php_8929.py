from proofcms.modules.php import cve_2024_8929

RUNTIME = {"detected": True, "version": "8.3.13", "source": "/:X-Powered-By"}


def test_8929_version_boundaries():
    assert cve_2024_8929.classify_version("7.4.33") == "LIKELY_VULNERABLE"
    assert cve_2024_8929.classify_version("8.1.0") == "LIKELY_VULNERABLE"
    assert cve_2024_8929.classify_version("8.1.30") == "LIKELY_VULNERABLE"
    assert cve_2024_8929.classify_version("8.1.31") == "PATCHED"
    assert cve_2024_8929.classify_version("8.2.25") == "LIKELY_VULNERABLE"
    assert cve_2024_8929.classify_version("8.2.26") == "PATCHED"
    assert cve_2024_8929.classify_version("8.3.13") == "LIKELY_VULNERABLE"
    assert cve_2024_8929.classify_version("8.3.14") == "PATCHED"
    assert cve_2024_8929.classify_version("8.4.0") == "PATCHED"
    assert cve_2024_8929.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_8929_affected_version_is_version_match_only():
    result = cve_2024_8929.check("https://fixture.test", php_runtime=RUNTIME)
    assert result.status == "LIKELY_VULNERABLE"
    assert result.confidence == "MEDIUM"
    assert result.exploit_available is False
    assert "Version match only" in result.detail
    assert "hostile MySQL server" in result.detail


def test_8929_patched_version_is_patched():
    result = cve_2024_8929.check(
        "https://fixture.test",
        php_runtime={"detected": True, "version": "8.3.14", "source": "/:X-Powered-By"},
    )
    assert result.status == "PATCHED"
    assert result.confidence == "HIGH"


def test_8929_unknown_version_is_inconclusive():
    result = cve_2024_8929.check(
        "https://fixture.test",
        php_runtime={"detected": True, "version": None, "source": "/:Set-Cookie"},
    )
    assert result.status == "INCONCLUSIVE"


def test_8929_without_php_is_not_detected():
    result = cve_2024_8929.check("https://fixture.test", php_runtime={"detected": False})
    assert result.status == "NOT_DETECTED"


def test_8929_metadata_is_passive():
    metadata = cve_2024_8929.metadata()
    assert metadata["exploit_modes"] == []
    assert metadata["exploit_available"] is False
    assert metadata["intrusive"] is False
    assert metadata["vulnerability_type"] == "Information Disclosure"
