from proofcms.modules.php import cve_2023_3824

RUNTIME = {"detected": True, "version": "8.2.7", "source": "/:X-Powered-By"}


def test_3824_version_boundaries():
    assert cve_2023_3824.classify_version("7.4.33") == "NOT_AFFECTED"
    assert cve_2023_3824.classify_version("8.0.0") == "LIKELY_VULNERABLE"
    assert cve_2023_3824.classify_version("8.0.29") == "LIKELY_VULNERABLE"
    assert cve_2023_3824.classify_version("8.0.30") == "PATCHED"
    assert cve_2023_3824.classify_version("8.1.21") == "LIKELY_VULNERABLE"
    assert cve_2023_3824.classify_version("8.1.22") == "PATCHED"
    assert cve_2023_3824.classify_version("8.2.7") == "LIKELY_VULNERABLE"
    assert cve_2023_3824.classify_version("8.2.8") == "PATCHED"
    assert cve_2023_3824.classify_version("8.3.0") == "PATCHED"
    assert cve_2023_3824.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_3824_affected_version_is_version_match_only():
    result = cve_2023_3824.check("https://fixture.test", php_runtime=RUNTIME)
    assert result.status == "LIKELY_VULNERABLE"
    assert result.confidence == "MEDIUM"
    assert result.exploit_available is False
    assert "Version match only" in result.detail
    assert "crafted phar" in result.detail


def test_3824_patched_version_is_patched():
    result = cve_2023_3824.check(
        "https://fixture.test",
        php_runtime={"detected": True, "version": "8.2.8", "source": "/:X-Powered-By"},
    )
    assert result.status == "PATCHED"
    assert result.confidence == "HIGH"


def test_3824_pre_branch_is_not_affected():
    result = cve_2023_3824.check(
        "https://fixture.test",
        php_runtime={"detected": True, "version": "7.4.33", "source": "/:X-Powered-By"},
    )
    assert result.status == "NOT_AFFECTED"


def test_3824_unknown_version_is_inconclusive():
    result = cve_2023_3824.check(
        "https://fixture.test",
        php_runtime={"detected": True, "version": None, "source": "/:Set-Cookie"},
    )
    assert result.status == "INCONCLUSIVE"


def test_3824_without_php_is_not_detected():
    result = cve_2023_3824.check("https://fixture.test", php_runtime={"detected": False})
    assert result.status == "NOT_DETECTED"


def test_3824_metadata_is_passive():
    metadata = cve_2023_3824.metadata()
    assert metadata["exploit_modes"] == []
    assert metadata["exploit_available"] is False
    assert metadata["intrusive"] is False
    assert metadata["vulnerability_type"] == "Buffer Overflow / Potential RCE"
