from __future__ import annotations

import re
from unittest.mock import patch

from proofcms.modules.wordpress import cve_2026_118423 as wplf

DATE = "Fri, 20 Nov 2026 21:00:00 GMT"


class _FakeClient:
    def __init__(self, marker_found: bool = True) -> None:
        self.marker_found = marker_found
        self.marker = ""

    def get(self, url: str, headers=None, timeout: int | None = None) -> dict[str, object]:
        if "page_id=1" in url:
            return {"status": 200, "body": '<p>[libre-form id=7]</p>'}
        if "readme.txt" in url:
            return {"status": 200, "body": "Stable tag: 1.5.0.1"}
        if "/wp-content/uploads/" in url and self.marker_found:
            return {"status": 200, "body": self.marker}
        return {"status": 404, "body": ""}

    def request(
        self,
        url: str,
        method: str = "GET",
        headers=None,
        data=None,
        timeout: int | None = None,
        follow_redirects: bool = True,
    ) -> dict[str, object]:
        payload = data if isinstance(data, bytes) else str(data or "").encode()
        found = re.search(rb"PROOFCMS_118423_[a-f0-9]{12}", payload)
        if found:
            self.marker = found.group(0).decode()
        return {"status": 200, "body": '{"ok":1,"submission_id":9}', "headers": {"Date": DATE}}


def test_118423_classify_version():
    assert wplf._classify("1.5.0.1") == "LIKELY_VULNERABLE"
    assert wplf._classify("1.4.3") == "LIKELY_VULNERABLE"
    assert wplf._classify(None) == "DETECTED_VERSION_UNKNOWN"


def test_118423_form_id_from_shortcode():
    with patch.object(wplf, "HttpClient", return_value=_FakeClient()):
        form = wplf._form_id(_FakeClient(), "https://fixture.test", 1, None)
    assert form == 7


def test_118423_candidate_paths_cover_timezone_and_clock_variants():
    paths = wplf._upload_urls(DATE, "proofcms.php")
    assert paths
    assert all(path.startswith("/wp-content/uploads/2026/11/lf_") for path in paths)
    assert any("proofcms.php" in path for path in paths)


def test_118423_upload_readback_confirms():
    with patch.object(wplf, "HttpClient", return_value=_FakeClient()):
        result = wplf.run_aggressive_probe("https://fixture.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["form_id"] == 7
    assert result.evidence["readback_path"]


def test_118423_no_readback_is_not_confirmed():
    with patch.object(wplf, "HttpClient", return_value=_FakeClient(marker_found=False)):
        result = wplf.run_aggressive_probe("https://fixture.test")
    assert result.status == "NOT_CONFIRMED"


def test_118423_safe_probe_sends_no_upload():
    with patch.object(wplf, "HttpClient", return_value=_FakeClient()):
        result = wplf.check("https://fixture.test", run_exploit_check=True, exploit_mode="safe")
    assert result.exploit_ran is False
