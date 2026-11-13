from unittest.mock import patch

from proofcms.modules.generic import cve_2025_55315


def test_55315_version_boundaries():
    assert cve_2025_55315.classify_version("2.3.5") == "LIKELY_VULNERABLE"
    assert cve_2025_55315.classify_version("2.3.6") == "PATCHED"
    assert cve_2025_55315.classify_version("8.0.20") == "LIKELY_VULNERABLE"
    assert cve_2025_55315.classify_version("8.0.21") == "PATCHED"
    assert cve_2025_55315.classify_version("9.0.9") == "LIKELY_VULNERABLE"
    assert cve_2025_55315.classify_version("9.0.10") == "PATCHED"
    assert cve_2025_55315.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_55315_safe_probe_vulnerable_connection_behavior():
    results = [
        {"closed": False, "status": "HTTP/1.1 200 OK", "bytes": 171},
        {"closed": False, "status": "HTTP/1.1 200 OK", "bytes": 171},
        {"closed": True, "status": "HTTP/1.1 200 OK", "bytes": 171},
    ]
    with patch.object(cve_2025_55315, "_send_chunk", side_effect=results):
        probe = cve_2025_55315.run_safe_probe("http://127.0.0.1:9219", timeout=1)
    assert probe["vulnerable"] is True
    assert probe["patched"] is False


def test_55315_safe_probe_patched_connection_behavior():
    results = [
        {"closed": False, "status": "HTTP/1.1 200 OK", "bytes": 171},
        {"closed": True, "status": "HTTP/1.1 200 OK", "bytes": 171},
        {"closed": True, "status": "HTTP/1.1 200 OK", "bytes": 171},
    ]
    with patch.object(cve_2025_55315, "_send_chunk", side_effect=results):
        probe = cve_2025_55315.run_safe_probe("http://127.0.0.1:9220", timeout=1)
    assert probe["vulnerable"] is False
    assert probe["patched"] is True


def test_55315_safe_probe_inconclusive_when_controls_fail():
    results = [
        {"closed": True, "status": "HTTP/1.1 200 OK", "bytes": 171},
        {"closed": True, "status": "HTTP/1.1 200 OK", "bytes": 171},
        {"closed": True, "status": "HTTP/1.1 200 OK", "bytes": 171},
    ]
    with patch.object(cve_2025_55315, "_send_chunk", side_effect=results):
        probe = cve_2025_55315.run_safe_probe("http://127.0.0.1:9220", timeout=1)
    assert probe["inconclusive"] is True


def test_55315_check_promotes_confirmed_probe():
    with patch.object(
        cve_2025_55315,
        "run_safe_probe",
        return_value={"vulnerable": True, "patched": False},
    ):
        result = cve_2025_55315.check(
            "https://fixture.test",
            run_exploit_check=True,
            exploit_mode="safe",
            timeout=1,
        )
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.exploit_ran is True


def test_55315_metadata_is_safe():
    metadata = cve_2025_55315.metadata()
    assert metadata["exploit_modes"] == ["safe"]
    assert metadata["intrusive"] is False
