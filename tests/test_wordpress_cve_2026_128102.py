from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.wordpress import cve_2026_128102 as rtmedia

PAGE = (
    'var rtMedia_plupload = {"rtMedia_plupload_config":'
    '{"url":"\\/upload\\/upload\\/"}};\n'
    'var config = {"rtmedia_upload_nonce":"abc123def4"};'
)


class _FakeClient:
    def __init__(self, nonce: bool = True, media_id: bool = True) -> None:
        self.nonce = nonce
        self.media_id = media_id

    def get(self, url: str, headers=None, timeout: int | None = None) -> dict[str, object]:
        if self.nonce and url.rstrip("/").endswith("/upload"):
            return {"status": 200, "body": PAGE}
        return {"status": 404, "body": "Not Found"}

    def post_multipart(
        self,
        url: str,
        fields: dict | None = None,
        files: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
    ) -> dict[str, object]:
        body = '{"media_id":"1"}' if self.media_id else "[]"
        return {"status": 200, "body": body}


def _timing(values: list[float]):
    return patch.object(rtmedia.time, "perf_counter", side_effect=values)


def test_128102_classify_version_boundaries():
    assert rtmedia._classify("4.7.17") == "LIKELY_VULNERABLE"
    assert rtmedia._classify("4.7.18") == "PATCHED"
    assert rtmedia._classify("4.7.19") == "PATCHED"
    assert rtmedia._classify(None) == "DETECTED_VERSION_UNKNOWN"


def test_128102_passive_detects_vulnerable_version():
    result = rtmedia.passive_result({"buddypress-media": {"found": True, "version": "4.7.17"}})
    assert result.status == "LIKELY_VULNERABLE"
    assert result.component_version == "4.7.17"


def test_128102_passive_detects_patched_version():
    result = rtmedia.passive_result({"buddypress-media": {"found": True, "version": "4.7.18"}})
    assert result.status == "PATCHED"


def test_128102_timing_delay_confirms():
    values = [0.0, 0.11, 0.2, 3.31]
    with patch.object(rtmedia, "HttpClient", return_value=_FakeClient()), _timing(values):
        result = rtmedia.run_aggressive_probe("https://fixture.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["delay_seconds"] == 3
    assert result.evidence["endpoint"] == "https://fixture.test/upload/upload/"


def test_128102_patched_timing_is_not_confirmed():
    values = [0.0, 0.05, 0.1, 0.16]
    with patch.object(rtmedia, "HttpClient", return_value=_FakeClient()), _timing(values):
        result = rtmedia.run_aggressive_probe("https://fixture.test")
    assert result.status == "NOT_CONFIRMED"
    assert result.confidence == "HIGH"


def test_128102_missing_nonce_is_blocked():
    with patch.object(rtmedia, "HttpClient", return_value=_FakeClient(nonce=False)):
        result = rtmedia.run_safe_probe("https://fixture.test")
    assert result.status == "BLOCKED_EXTERNAL"


def test_128102_missing_media_id_is_blocked():
    with patch.object(rtmedia, "HttpClient", return_value=_FakeClient(media_id=False)):
        result = rtmedia.run_safe_probe("https://fixture.test")
    assert result.status == "BLOCKED_EXTERNAL"


def test_128102_check_safe_and_aggressive_modes():
    values = [0.0, 0.05, 0.1, 1.2]
    with patch.object(rtmedia, "HttpClient", return_value=_FakeClient()), _timing(values):
        safe = rtmedia.check("https://fixture.test", run_exploit_check=True, exploit_mode="safe")
    assert safe.status == "VULNERABLE"
    assert safe.evidence["delay_seconds"] == 1

    values = [0.0, 0.05, 0.1, 3.2]
    with patch.object(rtmedia, "HttpClient", return_value=_FakeClient()), _timing(values):
        aggressive = rtmedia.check(
            "https://fixture.test", run_exploit_check=True, exploit_mode="aggressive"
        )
    assert aggressive.status == "VULNERABLE"
    assert aggressive.evidence["delay_seconds"] == 3


def test_128102_metadata_contract():
    meta = rtmedia.metadata()
    assert meta["cve"] == "CVE-2026-128102"
    assert meta["exploit_modes"] == ["safe", "aggressive"]
    assert meta["required_detectors"] == ["buddypress-media"]
    assert "4.7.18" in meta["affected_rule"]
