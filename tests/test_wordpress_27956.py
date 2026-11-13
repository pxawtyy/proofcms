from unittest.mock import patch

from proofcms.modules.wordpress import cve_2024_27956

PLUGINS = {
    "wp-automatic": {
        "found": True,
        "version": "3.92.0",
        "source": "/wp-content/plugins/wp-automatic/changelog",
        "version_confidence": "HIGH",
    }
}


def test_27956_version_boundaries():
    assert cve_2024_27956.classify_version("3.91.0") == "LIKELY_VULNERABLE"
    assert cve_2024_27956.classify_version("3.92.0") == "LIKELY_VULNERABLE"
    assert cve_2024_27956.classify_version("3.92.1") == "PATCHED"
    assert cve_2024_27956.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_27956_probe_confirms_sleep_differential():
    control = {"elapsed": 0.06, "status": 200, "csv": True}
    proof = {"elapsed": 4.02, "status": 200, "csv": True}
    with patch.object(cve_2024_27956, "_timed_query", side_effect=[control, proof]):
        result = cve_2024_27956.run_safe_probe("https://fixture.test", timeout=1)
    assert result["confirmed"] is True
    assert result["proof"]["elapsed"] == 4.02


def test_27956_probe_requires_csv_body():
    control = {"elapsed": 0.06, "status": 200, "csv": True}
    proof = {"elapsed": 4.02, "status": 200, "csv": False}
    with patch.object(cve_2024_27956, "_timed_query", side_effect=[control, proof]):
        result = cve_2024_27956.run_safe_probe("https://fixture.test", timeout=1)
    assert result["confirmed"] is False


def test_27956_check_promotes_confirmed_probe():
    probe = {
        "confirmed": True,
        "control": {"elapsed": 0.06},
        "proof": {"elapsed": 4.02},
        "proof_url": "https://fixture.test/csv.php",
    }
    with patch.object(cve_2024_27956, "run_safe_probe", return_value=probe):
        result = cve_2024_27956.check(
            "https://fixture.test",
            run_exploit_check=True,
            exploit_mode="safe",
            plugins=PLUGINS,
            timeout=1,
        )
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.exploit_ran is True


def test_27956_check_patched_version_skips_probe():
    patched = {"wp-automatic": {**PLUGINS["wp-automatic"], "version": "3.92.1"}}
    with patch.object(cve_2024_27956, "run_safe_probe") as probe:
        result = cve_2024_27956.check(
            "https://fixture.test",
            run_exploit_check=True,
            exploit_mode="safe",
            plugins=patched,
            timeout=1,
        )
    probe.assert_not_called()
    assert result.status == "PATCHED"


def test_27956_metadata_is_safe():
    metadata = cve_2024_27956.metadata()
    assert metadata["exploit_modes"] == ["safe"]
    assert metadata["intrusive"] is False
    assert metadata["vulnerability_type"] == "SQL Injection"
