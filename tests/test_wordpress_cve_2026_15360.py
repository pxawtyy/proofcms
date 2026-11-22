from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.wordpress import cve_2026_15360 as alm

BASELINE_BODY = '{"html":"<li>post</li>","meta":{"postcount":1,"totalposts":1}}'
EMPTY_BODY = '{"html":null,"meta":{"postcount":0,"totalposts":0}}'


class _FakeClient:
    def __init__(self, posts: bool = True, transport: bool = False) -> None:
        self.posts = posts
        self.transport = transport
        self.urls: list[str] = []

    def get(self, url: str, headers=None, timeout: int | None = None) -> dict[str, object]:
        self.urls.append(url)
        if self.transport:
            return {"status": 0, "error": {"type": "TransportError", "message": "boom"}}
        return {"status": 200, "body": BASELINE_BODY if self.posts else EMPTY_BODY}


def _timing(values: list[float]):
    return patch.object(alm.time, "perf_counter", side_effect=values)


def test_15360_classify_version_boundaries():
    assert alm._classify("8.0.0") == "LIKELY_VULNERABLE"
    assert alm._classify("8.0.1") == "PATCHED"
    assert alm._classify("8.1.0") == "PATCHED"
    assert alm._classify(None) == "DETECTED_VERSION_UNKNOWN"


def test_15360_core_gate():
    assert alm._core_supports_scalar_author_not_in("6.4.3") is False
    assert alm._core_supports_scalar_author_not_in("6.9.4") is False
    assert alm._core_supports_scalar_author_not_in("7.0") is True
    assert alm._core_supports_scalar_author_not_in("7.1.2") is True
    assert alm._core_supports_scalar_author_not_in(None) is True


def test_15360_passive_detects_vulnerable_and_patched():
    vulnerable = alm.passive_result({"ajax-load-more": {"found": True, "version": "8.0.0"}})
    assert vulnerable.status == "LIKELY_VULNERABLE"
    assert vulnerable.component_version == "8.0.0"

    patched = alm.passive_result({"ajax-load-more": {"found": True, "version": "8.0.1"}})
    assert patched.status == "PATCHED"


def test_15360_timing_delay_confirms():
    fake = _FakeClient()
    with patch.object(alm, "HttpClient", return_value=fake), _timing([0.0, 0.10, 0.20, 3.20]):
        result = alm.run_aggressive_probe("https://fixture.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["delay_seconds"] == 3
    assert result.evidence["payload"] == "author__not_in:SELECT(SLEEP(3))"
    assert "admin-ajax.php" in result.evidence["endpoint"]
    assert any("author__not_in%3ASELECT%28SLEEP%283%29%29" in url for url in fake.urls)


def test_15360_patched_timing_is_not_confirmed():
    with patch.object(alm, "HttpClient", return_value=_FakeClient()), _timing([0.0, 0.05, 0.10, 0.15]):
        result = alm.run_aggressive_probe("https://fixture.test")
    assert result.status == "NOT_CONFIRMED"
    assert result.confidence == "HIGH"


def test_15360_no_posts_is_blocked():
    with patch.object(alm, "HttpClient", return_value=_FakeClient(posts=False)):
        result = alm.run_safe_probe("https://fixture.test")
    assert result.status == "BLOCKED_EXTERNAL"
    assert result.evidence["meta"]["totalposts"] == 0


def test_15360_transport_error_is_error():
    with patch.object(alm, "HttpClient", return_value=_FakeClient(transport=True)):
        result = alm.run_safe_probe("https://fixture.test")
    assert result.status == "ERROR"
    assert result.confidence == "LOW"


def test_15360_old_core_is_blocked_instead_of_not_confirmed():
    with patch.object(alm, "HttpClient", return_value=_FakeClient()), _timing([0.0, 0.05, 0.10, 0.15]):
        result = alm.check(
            "https://fixture.test",
            cms_version="6.4.3",
            run_exploit_check=True,
            exploit_mode="aggressive",
        )
    assert result.status == "BLOCKED_EXTERNAL"
    assert "casts the scalar author__not_in" in result.detail


def test_15360_check_safe_and_aggressive_modes():
    with patch.object(alm, "HttpClient", return_value=_FakeClient()), _timing([0.0, 0.10, 0.20, 1.20]):
        safe = alm.check(
            "https://fixture.test",
            cms_version="7.0",
            run_exploit_check=True,
            exploit_mode="safe",
        )
    assert safe.status == "VULNERABLE"
    assert safe.evidence["delay_seconds"] == 1

    with patch.object(alm, "HttpClient", return_value=_FakeClient()), _timing([0.0, 0.10, 0.20, 3.20]):
        aggressive = alm.check(
            "https://fixture.test",
            cms_version="7.0",
            run_exploit_check=True,
            exploit_mode="aggressive",
        )
    assert aggressive.status == "VULNERABLE"
    assert aggressive.evidence["delay_seconds"] == 3


def test_15360_metadata_contract():
    meta = alm.metadata()
    assert meta["cve"] == "CVE-2026-15360"
    assert meta["exploit_modes"] == ["safe", "aggressive"]
    assert meta["required_detectors"] == ["ajax-load-more"]
    assert "8.0.1" in meta["affected_rule"]
