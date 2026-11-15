from __future__ import annotations

import re
from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_102789, cve_2026_105604, cve_2026_117551


class _FakeJDClient:
    def __init__(self, file_status: int = 200):
        self.file_status = file_status
        self.marker = ""
        self.form = (
            '<form action="/index.php?option=com_jdownloads&task=download.save" method="post" id="adminForm">'
            '<input type="file" name="file_upload_thumb[0]">'
            '<input type="hidden" name="cat_dir_org" value="2">'
            '<input type="hidden" name="0123456789abcdef0123456789abcdef" value="1">'
            "</form>"
        )

    def get(self, url: str, timeout: int | None = None) -> dict[str, object]:
        if "images/jdownloads/screenshots/" in url:
            return {"status": self.file_status, "body": self.marker if self.file_status == 200 else ""}
        return {"status": 200, "body": self.form}

    def request(self, url: str, method: str = "POST", headers=None, data=None, timeout=None, follow_redirects=False):
        text = data.decode("utf-8", "ignore") if isinstance(data, bytes) else str(data or "")
        match = re.search(r"PROOFCMS_JD_RCE_[a-f0-9]+", text)
        if match:
            self.marker = match.group(0)
        return {"status": 303, "body": "", "headers": {"Location": "/"}}


def test_jdownloads_version_boundaries():
    assert cve_2026_117551.classify_version("4.1.7") == "LIKELY_VULNERABLE"
    assert cve_2026_117551.classify_version("4.1.7 Stable") == "LIKELY_VULNERABLE"
    assert cve_2026_117551.classify_version("4.1.8") == "NOT_AFFECTED"
    assert cve_2026_117551.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_jdownloads_polyglot_executes():
    client = _FakeJDClient(file_status=200)
    with patch.object(cve_2026_117551, "HttpClient", return_value=client):
        result = cve_2026_117551.run_aggressive_probe(
            "https://target.test",
            form_url="https://target.test/index.php?option=com_jdownloads&view=form&layout=edit&catid=2",
        )
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["marker_executed"] is True
    assert result.evidence["filename"].endswith(".php")


def test_jdownloads_patched_upload_is_not_confirmed():
    client = _FakeJDClient(file_status=404)
    with patch.object(cve_2026_117551, "HttpClient", return_value=client):
        result = cve_2026_117551.run_aggressive_probe(
            "https://target.test",
            form_url="https://target.test/index.php?option=com_jdownloads&view=form&layout=edit&catid=2",
        )
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["marker_executed"] is False


def test_jdownloads_missing_form_is_blocked():
    class _NoFormClient:
        def get(self, url: str, timeout: int | None = None) -> dict[str, object]:
            return {"status": 200, "body": "<html>no upload form</html>"}

    with patch.object(cve_2026_117551, "HttpClient", return_value=_NoFormClient()):
        result = cve_2026_117551.run_aggressive_probe("https://target.test")
    assert result.status == "BLOCKED_EXTERNAL"


def test_djclassifieds_version_boundaries():
    assert cve_2026_105604.classify_version("3.11.2") == "LIKELY_VULNERABLE"
    assert cve_2026_105604.classify_version("3.11.3") == "NOT_AFFECTED"
    assert cve_2026_105604.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_djclassifieds_sleep_probe_confirms():
    ok = {"status": 200, "body": "djcf listing"}
    with patch.object(cve_2026_105604, "_timed_request", side_effect=[(ok, 0.2), (ok, 0.2), (ok, 2.2)]):
        result = cve_2026_105604.run_aggressive_probe("https://target.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["delta_seconds"] >= cve_2026_105604.SLEEP_THRESHOLD


def test_djclassifieds_patched_sleep_probe_is_not_confirmed():
    ok = {"status": 200, "body": "djcf listing"}
    with patch.object(cve_2026_105604, "_timed_request", side_effect=[(ok, 0.2), (ok, 0.2), (ok, 0.3)]):
        result = cve_2026_105604.run_aggressive_probe("https://target.test")
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["delta_seconds"] < cve_2026_105604.SLEEP_THRESHOLD


def test_djclassifieds_transport_error_is_reported():
    error = {"status": 0, "error": {"type": "URLError", "message": "down"}}
    with patch.object(cve_2026_105604, "_timed_request", side_effect=[(error, 0.0)]):
        result = cve_2026_105604.run_aggressive_probe("https://target.test")
    assert result.status == "ERROR"


class _FakeGridboxClient:
    def __init__(self, status: int = 500, sql_error: bool = True):
        self.status = status
        self.sql_error = sql_error

    def get(self, url: str, timeout: int | None = None) -> dict[str, object]:
        if self.status == 500 and self.sql_error:
            match = re.search(r"order=(proofcms_[a-f0-9]+)", url)
            column = match.group(1) if match else "proofcms_unknown"
            return {"status": 500, "body": f"Error: 1054 Unknown column 'p.{column}' in 'ORDER BY'"}
        return {"status": self.status, "body": ""}


def test_gridbox_102789_version_boundaries():
    assert cve_2026_102789.classify_version("2.20.0.2") == "LIKELY_VULNERABLE"
    assert cve_2026_102789.classify_version("2.20.5.0") == "NOT_AFFECTED"
    assert cve_2026_102789.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_gridbox_102789_error_signature_confirms():
    with patch.object(cve_2026_102789, "HttpClient", return_value=_FakeGridboxClient(500, True)):
        result = cve_2026_102789.run_aggressive_probe("https://target.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["sql_error"] is True


def test_gridbox_102789_patched_is_not_confirmed():
    with patch.object(cve_2026_102789, "HttpClient", return_value=_FakeGridboxClient(200, False)):
        result = cve_2026_102789.run_aggressive_probe("https://target.test")
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["sql_error"] is False


def test_gridbox_102789_transport_error_is_reported():
    class _DownClient:
        def get(self, url: str, timeout: int | None = None) -> dict[str, object]:
            return {"status": 0, "error": {"type": "URLError", "message": "down"}}

    with patch.object(cve_2026_102789, "HttpClient", return_value=_DownClient()):
        result = cve_2026_102789.run_aggressive_probe("https://target.test")
    assert result.status == "ERROR"
