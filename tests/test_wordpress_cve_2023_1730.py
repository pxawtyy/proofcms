from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.wordpress import cve_2023_1730 as supportcandy


def _timing(values: list[float]):
    return patch.object(supportcandy.time, "perf_counter", side_effect=values)


class _FakeRequest:
    def __init__(self, transport: bool = False) -> None:
        self.transport = transport
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, url: str, **kwargs):
        self.calls.append((url, kwargs))
        if self.transport:
            return {"status": 0, "error": {"type": "TransportError", "message": "boom"}}
        return {"status": 200, "body": "<html>home</html>"}


def test_2023_1730_classify_version_boundaries():
    assert supportcandy.classify_version("2.3.0") == "LIKELY_VULNERABLE"
    assert supportcandy.classify_version("3.1.4") == "LIKELY_VULNERABLE"
    assert supportcandy.classify_version("3.1.5") == "PATCHED"
    assert supportcandy.classify_version("3.3.6") == "PATCHED"
    assert supportcandy.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_2023_1730_passive_detects_vulnerable_and_patched():
    vulnerable = supportcandy.passive_result(
        {"supportcandy": {"found": True, "version": "2.3.0"}}
    )
    assert vulnerable.status == "LIKELY_VULNERABLE"
    assert vulnerable.component_version == "2.3.0"

    patched = supportcandy.passive_result(
        {"supportcandy": {"found": True, "version": "3.1.5"}}
    )
    assert patched.status == "PATCHED"

    missing = supportcandy.passive_result({})
    assert missing.status == "NOT_DETECTED"


def test_2023_1730_2x_range_is_advisory_only():
    finding = supportcandy.passive_result(
        {"supportcandy": {"found": True, "version": "2.3.0"}}
    )
    assert finding.status == "LIKELY_VULNERABLE"
    assert "introduced in 3.0.0" in finding.detail


def test_2023_1730_timing_delay_confirms():
    fake = _FakeRequest()
    with (
        patch.object(supportcandy, "request", fake),
        _timing([0.0, 0.10, 0.20, 0.25, 0.30, 3.40]),
    ):
        result = supportcandy.run_aggressive_probe("https://fixture.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["delay_seconds"] == 3
    assert fake.calls[0][0] == "https://fixture.test/"
    assert "wpsc_guest_login_auth" in fake.calls[0][1]["headers"]["Cookie"]
    assert "SLEEP(0)" in fake.calls[1][1]["headers"]["Cookie"]
    assert "SLEEP(3)" in fake.calls[2][1]["headers"]["Cookie"]


def test_2023_1730_patched_timing_is_not_confirmed():
    with (
        patch.object(supportcandy, "request", _FakeRequest()),
        _timing([0.0, 0.10, 0.20, 0.25, 0.30, 0.40]),
    ):
        result = supportcandy.run_aggressive_probe("https://fixture.test")
    assert result.status == "NOT_CONFIRMED"
    assert result.confidence == "HIGH"


def test_2023_1730_transport_error_is_error():
    with patch.object(supportcandy, "request", _FakeRequest(transport=True)):
        result = supportcandy.run_safe_probe("https://fixture.test")
    assert result.status == "ERROR"
    assert result.confidence == "LOW"


def test_2023_1730_check_selects_modes():
    with patch.object(supportcandy, "run_safe_probe", return_value=supportcandy.passive_result({})) as safe:
        supportcandy.check("https://fixture.test", run_exploit_check=True, exploit_mode="safe")
        safe.assert_called_once()
    with patch.object(
        supportcandy, "run_aggressive_probe", return_value=supportcandy.passive_result({})
    ) as aggressive:
        supportcandy.check("https://fixture.test", run_exploit_check=True, exploit_mode="aggressive")
        aggressive.assert_called_once()


def test_2023_1730_metadata_contract():
    meta = supportcandy.metadata()
    assert meta["cve"] == "CVE-2023-1730"
    assert meta["cms"] == "wordpress"
    assert meta["exploit_modes"] == ["safe", "aggressive"]
    assert meta["required_detectors"] == ["supportcandy"]
    assert "3.1.5" in meta["affected_rule"]
