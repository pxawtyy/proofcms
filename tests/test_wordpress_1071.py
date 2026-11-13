from unittest.mock import patch

from proofcms.modules.wordpress import cve_2024_1071

PLUGINS = {
    "ultimate-member": {
        "found": True,
        "version": "2.8.2",
        "source": "/wp-content/plugins/ultimate-member/readme.txt",
        "version_confidence": "HIGH",
    }
}


def test_1071_version_boundaries():
    assert cve_2024_1071.classify_version("2.1.2") == "NOT_AFFECTED"
    assert cve_2024_1071.classify_version("2.1.3") == "LIKELY_VULNERABLE"
    assert cve_2024_1071.classify_version("2.8.2") == "LIKELY_VULNERABLE"
    assert cve_2024_1071.classify_version("2.8.3") == "PATCHED"
    assert cve_2024_1071.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_1071_directory_hash_matches_plugin_formula():
    assert cve_2024_1071.hash_for_post(5) == "ce234"


def test_1071_probe_confirms_sleep_differential():
    discovery = {"nonce": "abc", "directory_id": "ce234", "source_path": "/", "attempts": []}
    control = {"elapsed": 0.4, "status": 200, "valid": True, "total_users": 1}
    proof = {"elapsed": 4.0, "status": 200, "valid": True, "total_users": 1}
    with (
        patch.object(cve_2024_1071, "_discover", return_value=discovery),
        patch.object(cve_2024_1071, "_timed", side_effect=[control, proof]),
    ):
        result = cve_2024_1071.run_safe_probe("https://fixture.test", timeout=1)
    assert result["confirmed"] is True
    assert result["proof"]["elapsed"] == 4.0


def test_1071_probe_without_nonce_is_not_confirmed():
    discovery = {"nonce": None, "directory_id": None, "source_path": None, "attempts": ["/"]}
    with patch.object(cve_2024_1071, "_discover", return_value=discovery):
        result = cve_2024_1071.run_safe_probe("https://fixture.test", timeout=1)
    assert result["confirmed"] is False
    assert result["proof"] is None


def test_1071_check_promotes_confirmed_probe():
    probe = {
        "confirmed": True,
        "discovery": {"nonce": "abc", "directory_id": "ce234"},
        "control": {"elapsed": 0.4},
        "proof": {"elapsed": 4.0},
        "proof_url": "https://fixture.test/wp-admin/admin-ajax.php",
    }
    with patch.object(cve_2024_1071, "run_safe_probe", return_value=probe):
        result = cve_2024_1071.check(
            "https://fixture.test",
            run_exploit_check=True,
            exploit_mode="safe",
            plugins=PLUGINS,
            timeout=1,
        )
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.exploit_ran is True


def test_1071_check_patched_version_skips_probe():
    patched = {"ultimate-member": {**PLUGINS["ultimate-member"], "version": "2.8.3"}}
    with patch.object(cve_2024_1071, "run_safe_probe") as probe:
        result = cve_2024_1071.check(
            "https://fixture.test",
            run_exploit_check=True,
            exploit_mode="safe",
            plugins=patched,
            timeout=1,
        )
    probe.assert_not_called()
    assert result.status == "PATCHED"


def test_1071_metadata_is_safe():
    metadata = cve_2024_1071.metadata()
    assert metadata["exploit_modes"] == ["safe"]
    assert metadata["intrusive"] is False
    assert metadata["vulnerability_type"] == "SQL Injection"
