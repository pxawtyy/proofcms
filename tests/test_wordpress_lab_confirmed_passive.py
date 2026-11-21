from __future__ import annotations

from unittest.mock import patch

from proofcms.core.models import Finding
from proofcms.modules.wordpress import (
    cve_2026_73343,
    cve_2026_119977,
    cve_2026_125771,
    cve_2026_129048,
)


class _FakeClient:
    """HttpClient double that permits GET only, so any mutation fails loudly."""

    def __init__(self, body: str) -> None:
        self.body = body
        self.get_urls: list[str] = []

    def get(self, url: str, headers=None, timeout: int | None = None) -> dict[str, object]:
        self.get_urls.append(url)
        return {"status": 200, "body": self.body, "headers": {}, "final_url": url}

    def request(self, *args, **kwargs) -> dict[str, object]:
        raise AssertionError("safe mode must not issue a non-GET (mutating) request")

    post = request


# --- CVE-2026-73343 (WP Compress) ------------------------------------------


def test_73343_classify_vulnerable_and_patched():
    assert cve_2026_73343._classify("7.10.09") == "LIKELY_VULNERABLE"
    assert cve_2026_73343._classify("7.19.99") == "LIKELY_VULNERABLE"
    assert cve_2026_73343._classify("7.20.01") == "NOT_AFFECTED"
    assert cve_2026_73343._classify("7.21.0") == "NOT_AFFECTED"
    assert cve_2026_73343._classify(None) == "DETECTED_VERSION_UNKNOWN"
    assert cve_2026_73343._classify("garbage") == "DETECTED_VERSION_UNKNOWN"


def test_73343_check_is_passive_and_uses_readme_version():
    fake = _FakeClient("Stable tag: 7.10.09\n")
    with patch.object(cve_2026_73343, "HttpClient", return_value=fake):
        result = cve_2026_73343.check("https://fixture.test", run_exploit_check=True)
    assert isinstance(result, Finding)
    assert result.status == "LIKELY_VULNERABLE"
    assert result.component_version == "7.10.09"
    assert result.exploit_ran is False
    assert fake.get_urls and "readme.txt" in fake.get_urls[0]


def test_73343_check_without_exploit_request_is_passive():
    with patch.object(cve_2026_73343, "HttpClient") as client:
        result = cve_2026_73343.check("https://fixture.test", plugins={"wp_compress": {"found": True, "version": "7.20.01"}})
    client.assert_not_called()
    assert result.status == "NOT_AFFECTED"
    assert result.exploit_ran is False


def test_73343_metadata_is_safe_only():
    meta = cve_2026_73343.metadata()
    assert meta["exploit_modes"] == ["safe"]
    assert meta["intrusive"] is False
    assert meta["exploit_available"] is True
    assert meta["cms"] == "wordpress"
    assert cve_2026_73343.EXPLOIT_MODES == ["safe"]
    assert cve_2026_73343.INTRUSIVE is False


# --- CVE-2026-119977 (WordPress core) --------------------------------------


def test_119977_classify_vulnerable_and_patched():
    assert cve_2026_119977._classify("7.1.3") == "LIKELY_VULNERABLE"
    assert cve_2026_119977._classify("6.4.3") == "LIKELY_VULNERABLE"
    assert cve_2026_119977._classify("7.1.4") == "NOT_AFFECTED"
    assert cve_2026_119977._classify("4.6.9") == "NOT_AFFECTED"
    assert cve_2026_119977._classify(None) == "DETECTED_VERSION_UNKNOWN"


def test_119977_check_is_passive_and_uses_core_readme():
    fake = _FakeClient("<html><head></head><body><h1>WordPress</h1><p>Version 7.1.3</p></body></html>")
    with patch.object(cve_2026_119977, "HttpClient", return_value=fake):
        result = cve_2026_119977.check("https://fixture.test", run_exploit_check=True)
    assert isinstance(result, Finding)
    assert result.status == "LIKELY_VULNERABLE"
    assert result.component_version == "7.1.3"
    assert result.exploit_ran is False
    assert fake.get_urls and "readme.html" in fake.get_urls[0]


def test_119977_check_without_exploit_request_is_passive():
    with patch.object(cve_2026_119977, "HttpClient") as client:
        result = cve_2026_119977.check("https://fixture.test", cms_version="7.1.4")
    client.assert_not_called()
    assert result.status == "NOT_AFFECTED"
    assert result.exploit_ran is False


def test_119977_metadata_is_safe_only():
    meta = cve_2026_119977.metadata()
    assert meta["exploit_modes"] == ["safe"]
    assert meta["intrusive"] is False
    assert meta["exploit_available"] is True
    assert meta["cms"] == "wordpress"
    assert cve_2026_119977.EXPLOIT_MODES == ["safe"]
    assert cve_2026_119977.INTRUSIVE is False


# --- CVE-2026-125771 (MCP Server for WordPress) ----------------------------


def test_125771_classify_vulnerable_and_patched():
    assert cve_2026_125771._classify("2.0.3") == "LIKELY_VULNERABLE"
    assert cve_2026_125771._classify("2.0.0") == "LIKELY_VULNERABLE"
    assert cve_2026_125771._classify("2.0.4") == "NOT_AFFECTED"
    assert cve_2026_125771._classify("2.1.0") == "NOT_AFFECTED"
    assert cve_2026_125771._classify(None) == "DETECTED_VERSION_UNKNOWN"


def test_125771_check_is_passive_and_uses_manifest_version():
    fake = _FakeClient("Stable tag: 2.0.3\n")
    with patch.object(cve_2026_125771, "HttpClient", return_value=fake):
        result = cve_2026_125771.check("https://fixture.test", run_exploit_check=True)
    assert isinstance(result, Finding)
    assert result.status == "LIKELY_VULNERABLE"
    assert result.component_version == "2.0.3"
    assert result.exploit_ran is False
    assert fake.get_urls and "readme.txt" in fake.get_urls[0]


def test_125771_check_without_exploit_request_is_passive():
    with patch.object(cve_2026_125771, "HttpClient") as client:
        result = cve_2026_125771.check("https://fixture.test", plugins={"mcp_server": {"found": True, "version": "2.0.4"}})
    client.assert_not_called()
    assert result.status == "NOT_AFFECTED"
    assert result.exploit_ran is False


def test_125771_metadata_is_safe_only():
    meta = cve_2026_125771.metadata()
    assert meta["exploit_modes"] == ["safe"]
    assert meta["intrusive"] is False
    assert meta["exploit_available"] is True
    assert meta["cms"] == "wordpress"
    assert cve_2026_125771.EXPLOIT_MODES == ["safe"]
    assert cve_2026_125771.INTRUSIVE is False


# --- CVE-2026-129048 (WP Photo Album Plus) ---------------------------------


def test_129048_classify_vulnerable_and_patched():
    assert cve_2026_129048._classify("9.3.06.003") == "LIKELY_VULNERABLE"
    assert cve_2026_129048._classify("9.3.6.3") == "LIKELY_VULNERABLE"
    assert cve_2026_129048._classify("9.3.07.001") == "NOT_AFFECTED"
    assert cve_2026_129048._classify("9.3.07.000") == "LIKELY_VULNERABLE"
    assert cve_2026_129048._classify(None) == "DETECTED_VERSION_UNKNOWN"


def test_129048_check_is_passive_and_uses_readme_version():
    fake = _FakeClient("Stable tag: 9.3.06.003\n")
    with patch.object(cve_2026_129048, "HttpClient", return_value=fake):
        result = cve_2026_129048.check("https://fixture.test", run_exploit_check=True)
    assert isinstance(result, Finding)
    assert result.status == "LIKELY_VULNERABLE"
    assert result.component_version == "9.3.06.003"
    assert result.exploit_ran is False
    assert fake.get_urls and "readme.txt" in fake.get_urls[0]


def test_129048_check_without_exploit_request_is_passive():
    with patch.object(cve_2026_129048, "HttpClient") as client:
        result = cve_2026_129048.check("https://fixture.test", plugins={"wppa": {"found": True, "version": "9.3.07.001"}})
    client.assert_not_called()
    assert result.status == "NOT_AFFECTED"
    assert result.exploit_ran is False


def test_129048_metadata_is_safe_only():
    meta = cve_2026_129048.metadata()
    assert meta["exploit_modes"] == ["safe"]
    assert meta["intrusive"] is False
    assert meta["exploit_available"] is True
    assert meta["cms"] == "wordpress"
    assert cve_2026_129048.EXPLOIT_MODES == ["safe"]
    assert cve_2026_129048.INTRUSIVE is False
