from __future__ import annotations

import json
from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_105606, cve_2026_107904

TOKEN = "a" * 32


class _FakeUploadClient:
    def __init__(self, accept_upload: bool = True) -> None:
        self.accept_upload = accept_upload

    def get(self, url: str, headers=None, timeout: int | None = None) -> dict[str, object]:
        if url.endswith("/index.php"):
            return {"status": 200, "body": f'<input name="{TOKEN}" value="1">'}
        if "/tmp/" in url:
            return {"status": 200, "body": "PROOFCMS_CT_MARKER"}
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
        if self.accept_upload:
            body = json.dumps({"status": "success", "filename": "ct_123_uploadedfile_proofcms-marker.svg"})
        else:
            body = json.dumps({"error": "Unable to upload the file."})
        return {"status": 200, "body": body}


def test_customtables_105606_version_boundaries():
    assert cve_2026_105606.classify_version("3.7.7") == "LIKELY_VULNERABLE"
    assert cve_2026_105606.classify_version("3.7.8") == "NOT_AFFECTED"
    assert cve_2026_105606.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_customtables_105606_passive_result():
    result = cve_2026_105606.passive_result({"customtables": {"found": True, "version": "3.7.7"}})
    assert result.status == "LIKELY_VULNERABLE"
    assert result.exploit_available is True


def test_customtables_105606_upload_confirms():
    with patch.object(cve_2026_105606, "HttpClient", return_value=_FakeUploadClient()):
        result = cve_2026_105606.run_aggressive_probe("https://target.test")
    assert result.status == "VULNERABLE_UPLOAD_ONLY"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["marker_found"] is True


def test_customtables_105606_rejected_upload_is_not_affected():
    with patch.object(cve_2026_105606, "HttpClient", return_value=_FakeUploadClient(accept_upload=False)):
        result = cve_2026_105606.run_aggressive_probe("https://target.test")
    assert result.status == "NOT_AFFECTED"
    assert result.evidence["filename"] == ""


def test_customtables_105606_safe_probe_sends_nothing():
    with patch.object(cve_2026_105606, "HttpClient", return_value=_FakeUploadClient()):
        result = cve_2026_105606.check(
            "https://target.test",
            run_exploit_check=True,
            exploit_mode="safe",
            plugins={"customtables": {"found": True, "version": "3.7.7"}},
        )
    assert result.status == "BLOCKED_EXTERNAL"
    assert result.exploit_ran is False


def test_easyfileuploader_107904_version_boundaries():
    assert cve_2026_107904.classify_version("2.9.2.1") == "LIKELY_VULNERABLE"
    assert cve_2026_107904.classify_version("2.9.6") == "LIKELY_VULNERABLE"
    assert cve_2026_107904.classify_version("2.9.7") == "NOT_AFFECTED"
    assert cve_2026_107904.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_easyfileuploader_107904_passive_result():
    result = cve_2026_107904.passive_result({"easyfileuploader": {"found": True, "version": "2.9.2.1"}})
    assert result.status == "LIKELY_VULNERABLE"
