from __future__ import annotations

import re
from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_102785


class _FakeYooClient:
    def __init__(self, exploit_status: int = 500, rce_status: int = 200, page_body: str | None = None) -> None:
        self.exploit_status = exploit_status
        self.rce_status = rce_status
        self.page_body = page_body or (
            '<html><body><img src="/index.php/component/ajax?p=cache/ab/proofcms-yoo-polyglot-abcd1234.jpg'
            '&amp;src=images/proofcms-yoo-polyglot.jpg&amp;thumbnail=300,90,&amp;hash=deadbeef"></body></html>'
        )
        self.marker = "PROOFCMS_YOO_RCE_abcd1234"

    def get(self, url: str, timeout: int | None = None) -> dict[str, object]:
        if "SAVE=" in url:
            return {"status": self.exploit_status, "body": ""}
        if re.search(r"/images/proofcms_[a-f0-9]+\.php$", url):
            return {"status": self.rce_status, "body": self.marker if self.rce_status == 200 else ""}
        if "images/proofcms-yoo-polyglot.jpg" in url:
            return {"status": 200, "body": f"JPEGDATA{self.marker}TAIL"}
        return {"status": 200, "body": self.page_body}


def test_yootheme_102785_version_boundaries():
    assert cve_2026_102785.classify_version("5.0.0") == "LIKELY_VULNERABLE"
    assert cve_2026_102785.classify_version("5.0.52") == "LIKELY_VULNERABLE"
    assert cve_2026_102785.classify_version("5.0.53") == "NOT_AFFECTED"
    assert cve_2026_102785.classify_version("4.9.9") == "NOT_AFFECTED"
    assert cve_2026_102785.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_yootheme_102785_signature_reuse_confirms():
    client = _FakeYooClient(exploit_status=500, rce_status=200)
    with patch.object(cve_2026_102785, "HttpClient", return_value=client):
        result = cve_2026_102785.run_aggressive_probe("https://target.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["executed"] is True
    assert result.evidence["cachekey"] == "abcd1234"
    assert result.evidence["write_path"].endswith(".php")


def test_yootheme_102785_patched_control_is_not_confirmed():
    client = _FakeYooClient(exploit_status=400, rce_status=404)
    with patch.object(cve_2026_102785, "HttpClient", return_value=client):
        result = cve_2026_102785.run_aggressive_probe("https://target.test")
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["executed"] is False
    assert result.evidence["file_readable"] is False


def test_yootheme_102785_missing_image_url_is_blocked():
    client = _FakeYooClient(page_body="<html><body>no image transformation here</body></html>")
    with patch.object(cve_2026_102785, "HttpClient", return_value=client):
        result = cve_2026_102785.run_aggressive_probe("https://target.test")
    assert result.status == "BLOCKED_EXTERNAL"
    assert result.exploit_ran is False


def test_yootheme_102785_explicit_image_url_skips_discovery():
    client = _FakeYooClient(exploit_status=500, rce_status=200)
    image_url = (
        "https://target.test/index.php/component/ajax?p=cache/ab/foo-1234abcd.jpg"
        "&src=images/foo.jpg&thumbnail=100,100,&hash=abcdef12"
    )
    with patch.object(cve_2026_102785, "HttpClient", return_value=client):
        result = cve_2026_102785.run_aggressive_probe(
            "https://target.test", image_url=image_url, marker="PROOFCMS_YOO_RCE_abcd1234"
        )
    assert result.status == "VULNERABLE"
    assert result.evidence["image_url"] == image_url
    assert result.evidence["cachekey"] == "1234abcd"


def test_yootheme_102785_transport_error_is_reported():
    class _DownClient:
        def get(self, url: str, timeout: int | None = None) -> dict[str, object]:
            return {"status": 0, "error": {"type": "URLError", "message": "down"}}

    with patch.object(cve_2026_102785, "HttpClient", return_value=_DownClient()):
        result = cve_2026_102785.run_aggressive_probe("https://target.test")
    assert result.status == "ERROR"
