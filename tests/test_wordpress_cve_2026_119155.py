from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.wordpress import cve_2026_119155 as wpforo

FORUM_PAGE = (
    'var wpforo = {"nonces":{"wpforo_get_member_template":"abc123def4",'
    '"wpforo_quote_ajax":"1111111111"}};'
)


class _FakeClient:
    def __init__(self, nonce: bool = True) -> None:
        self.nonce = nonce

    def get(self, url: str, headers=None, timeout: int | None = None) -> dict[str, object]:
        if self.nonce and url.rstrip("/").endswith("/community"):
            return {"status": 200, "body": FORUM_PAGE}
        return {"status": 404, "body": "Not Found"}

    def request(
        self,
        url: str,
        method: str = "GET",
        headers=None,
        data=None,
        timeout: int | None = None,
        follow_redirects: bool = True,
    ) -> dict[str, object]:
        return {"status": 200, "body": '{"success":false}'}


def _timing(values: list[float]):
    return patch.object(wpforo.time, "perf_counter", side_effect=values)


def test_119155_classify_version_boundaries():
    assert wpforo._classify("3.2.2") == "LIKELY_VULNERABLE"
    assert wpforo._classify("3.2.3") == "PATCHED"
    assert wpforo._classify("3.2.4") == "PATCHED"
    assert wpforo._classify(None) == "DETECTED_VERSION_UNKNOWN"


def test_119155_passive_detects_vulnerable_version():
    result = wpforo.passive_result({"wpforo": {"found": True, "version": "3.2.2"}})
    assert result.status == "LIKELY_VULNERABLE"
    assert result.component_version == "3.2.2"


def test_119155_passive_detects_patched_version():
    result = wpforo.passive_result({"wpforo": {"found": True, "version": "3.2.3"}})
    assert result.status == "PATCHED"


def test_119155_passive_not_detected():
    result = wpforo.passive_result({})
    assert result.status == "NOT_DETECTED"


def test_119155_timing_delay_confirms():
    # baseline 0.05/0.05, payload 3.00/3.10
    values = [0.0, 0.05, 0.10, 0.15, 0.20, 3.20, 3.30, 6.40]
    with patch.object(wpforo, "HttpClient", return_value=_FakeClient()), _timing(values):
        result = wpforo.run_aggressive_probe("https://fixture.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["slug"] == "community"
    assert result.evidence["delay_seconds"] == 3


def test_119155_patched_timing_is_not_confirmed():
    # baseline 0.05/0.05, payload 0.06/0.07
    values = [0.0, 0.05, 0.10, 0.15, 0.20, 0.26, 0.30, 0.37]
    with patch.object(wpforo, "HttpClient", return_value=_FakeClient()), _timing(values):
        result = wpforo.run_aggressive_probe("https://fixture.test")
    assert result.status == "NOT_CONFIRMED"
    assert result.confidence == "HIGH"


def test_119155_missing_nonce_is_blocked():
    with patch.object(wpforo, "HttpClient", return_value=_FakeClient(nonce=False)):
        result = wpforo.run_safe_probe("https://fixture.test")
    assert result.status == "BLOCKED_EXTERNAL"
    assert result.exploit_ran is True


def test_119155_check_safe_and_aggressive_modes():
    values = [0.0, 0.05, 0.10, 0.15, 0.20, 1.20, 1.30, 2.40]
    with patch.object(wpforo, "HttpClient", return_value=_FakeClient()), _timing(values):
        safe = wpforo.check("https://fixture.test", run_exploit_check=True, exploit_mode="safe")
    assert safe.status == "VULNERABLE"
    assert safe.evidence["delay_seconds"] == 1

    values = [0.0, 0.05, 0.10, 0.15, 0.20, 3.20, 3.30, 6.40]
    with patch.object(wpforo, "HttpClient", return_value=_FakeClient()), _timing(values):
        aggressive = wpforo.check(
            "https://fixture.test", run_exploit_check=True, exploit_mode="aggressive"
        )
    assert aggressive.status == "VULNERABLE"
    assert aggressive.evidence["delay_seconds"] == 3


def test_119155_metadata_contract():
    meta = wpforo.metadata()
    assert meta["cve"] == "CVE-2026-119155"
    assert meta["exploit_modes"] == ["safe", "aggressive"]
    assert meta["required_detectors"] == ["wpforo"]
    assert "3.2.3" in meta["affected_rule"]
