from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.wordpress import cve_2026_109197 as wpdk

PAGE = """
<div class="wdk-field wdk-col wdk-slider-range-col SLIDER_RANGE wdk_field_id_7">
  <div class="hidden config-range" data-min="0" data-max="250000"></div>
  <input id="wdk_field_7_min" name="field_7_min" type="text" />
  <input id="wdk_field_7_max" name="field_7_max" type="text" />
</div>
"""


class _FakeClient:
    def __init__(self, page: bool = True, transport: bool = False) -> None:
        self.page = page
        self.transport = transport
        self.posts: list[dict] = []

    def get(self, url: str, headers=None, timeout: int | None = None) -> dict[str, object]:
        if self.page:
            return {"status": 200, "body": PAGE, "final_url": url}
        return {"status": 404, "body": "Not Found"}

    def post(
        self,
        url: str,
        data=None,
        fields=None,
        files=None,
        headers=None,
        timeout: int | None = None,
    ) -> dict[str, object]:
        self.posts.append({"url": url, "data": data})
        if self.transport:
            return {"status": 0, "error": {"type": "TransportError", "message": "boom"}}
        return {"status": 200, "body": "ok"}


def _timing(values: list[float]):
    return patch.object(wpdk.time, "perf_counter", side_effect=values)


def test_109197_classify_version_boundaries():
    assert wpdk._classify("1.5.9") == "LIKELY_VULNERABLE"
    assert wpdk._classify("1.6.0") == "LIKELY_VULNERABLE"
    assert wpdk._classify("1.6.1") == "PATCHED"
    assert wpdk._classify("1.7.0") == "PATCHED"
    assert wpdk._classify(None) == "DETECTED_VERSION_UNKNOWN"


def test_109197_passive_detects_vulnerable_and_patched():
    vulnerable = wpdk.passive_result({"wpdirectorykit": {"found": True, "version": "1.5.9"}})
    assert vulnerable.status == "LIKELY_VULNERABLE"
    assert vulnerable.component_version == "1.5.9"

    patched = wpdk.passive_result({"wpdirectorykit": {"found": True, "version": "1.6.1"}})
    assert patched.status == "PATCHED"


def test_109197_parses_slider_field_and_type_order():
    assert wpdk._slider_fields(PAGE) == [("7", "250000")]
    assert wpdk._candidate_types("250000")[0] == "NUMBER"
    assert wpdk._candidate_types("2026-01-01")[0] == "DATE"
    assert wpdk._candidate_types("")[0] == "NUMBER"


def test_109197_timing_delay_confirms():
    values = [0.0, 0.10, 0.20, 3.20]
    fake = _FakeClient()
    with patch.object(wpdk, "HttpClient", return_value=fake), _timing(values):
        result = wpdk.run_aggressive_probe("https://fixture.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["delay_seconds"] == 3
    assert result.evidence["field_id"] == "7"
    assert result.evidence["field_type"] == "NUMBER"
    assert fake.posts[-1]["data"] == {"idfield": "7_NUMBER+(SELECT SLEEP(3))-- -"}


def test_109197_patched_timing_is_not_confirmed():
    values = [index * 0.01 for index in range(200)]
    fake = _FakeClient()
    with patch.object(wpdk, "HttpClient", return_value=fake), _timing(values):
        result = wpdk.run_aggressive_probe("https://fixture.test")
    assert result.status == "NOT_CONFIRMED"
    assert result.confidence == "HIGH"
    assert result.evidence["tested_types"] > 1


def test_109197_no_slider_page_is_blocked():
    with patch.object(wpdk, "HttpClient", return_value=_FakeClient(page=False)):
        result = wpdk.run_safe_probe("https://fixture.test")
    assert result.status == "BLOCKED_EXTERNAL"
    assert result.exploit_ran is True


def test_109197_transport_error_is_error():
    with patch.object(wpdk, "HttpClient", return_value=_FakeClient(transport=True)):
        result = wpdk.run_safe_probe("https://fixture.test")
    assert result.status == "ERROR"
    assert result.confidence == "LOW"


def test_109197_check_safe_and_aggressive_modes():
    values = [0.0, 0.10, 0.20, 1.20]
    with patch.object(wpdk, "HttpClient", return_value=_FakeClient()), _timing(values):
        safe = wpdk.check("https://fixture.test", run_exploit_check=True, exploit_mode="safe")
    assert safe.status == "VULNERABLE"
    assert safe.evidence["delay_seconds"] == 1

    values = [0.0, 0.10, 0.20, 3.20]
    with patch.object(wpdk, "HttpClient", return_value=_FakeClient()), _timing(values):
        aggressive = wpdk.check(
            "https://fixture.test", run_exploit_check=True, exploit_mode="aggressive"
        )
    assert aggressive.status == "VULNERABLE"
    assert aggressive.evidence["delay_seconds"] == 3


def test_109197_metadata_contract():
    meta = wpdk.metadata()
    assert meta["cve"] == "CVE-2026-109197"
    assert meta["exploit_modes"] == ["safe", "aggressive"]
    assert meta["required_detectors"] == ["wpdirectorykit"]
    assert "1.6.1" in meta["affected_rule"]
