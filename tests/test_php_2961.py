from unittest.mock import patch

from proofcms.modules.php import cve_2024_2961

RUNTIME = {"detected": True, "version": "8.3.4", "source": "/:X-Powered-By"}


def test_2961_version_boundaries():
    assert cve_2024_2961.classify_version("5.6.0") == "LIKELY_VULNERABLE"
    assert cve_2024_2961.classify_version("8.3.6") == "LIKELY_VULNERABLE"
    assert cve_2024_2961.classify_version("8.3.7") == "PATCHED"
    assert cve_2024_2961.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_2961_safe_probe_confirms_file_read_precondition():
    response = {
        "status": 200,
        "body": "File contents: cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaA==",
        "body_hash": "x",
    }
    with patch.object(cve_2024_2961, "HttpClient") as client:
        client.return_value.request.return_value = response
        result = cve_2024_2961.check(
            "https://fixture.test",
            run_exploit_check=True,
            exploit_mode="safe",
            php_runtime=RUNTIME,
            timeout=1,
        )
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["file_read"] is True


def test_2961_patched_version_skips_probe():
    with patch.object(cve_2024_2961, "HttpClient") as client:
        result = cve_2024_2961.check(
            "https://fixture.test",
            run_exploit_check=True,
            php_runtime={"detected": True, "version": "8.4.27", "source": "/:X-Powered-By"},
            timeout=1,
        )
    client.assert_not_called()
    assert result.status == "PATCHED"


def test_2961_metadata_is_safe():
    metadata = cve_2024_2961.metadata()
    assert metadata["exploit_modes"] == ["safe"]
    assert metadata["intrusive"] is False
