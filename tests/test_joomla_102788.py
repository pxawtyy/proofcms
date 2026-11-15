from __future__ import annotations

import re
from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_102788


class _FakeStoreClient:
    def __init__(self, error_status: int = 500, page_body: str = "") -> None:
        self.error_status = error_status
        self.page_body = page_body

    def get(self, url: str, timeout: int | None = None) -> dict[str, object]:
        if "proofcms_" in url:
            match = re.search(r"sort-by=(proofcms_[a-f0-9]+)", url)
            column = match.group(1) if match else "proofcms_unknown"
            body = f"Error: 1054 Unknown column 'p.{column}' in 'ORDER BY'" if self.error_status == 500 else ""
            return {"status": self.error_status, "body": body}
        if "sort-by=" in url:
            return {"status": 200, "body": ""}
        return {"status": 200, "body": self.page_body}


def test_gridbox_102788_version_boundaries():
    assert cve_2026_102788.classify_version("2.20.0.2") == "LIKELY_VULNERABLE"
    assert cve_2026_102788.classify_version("2.20.4.2") == "LIKELY_VULNERABLE"
    assert cve_2026_102788.classify_version("2.20.5.0") == "NOT_AFFECTED"
    assert cve_2026_102788.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_gridbox_102788_error_probe_confirms():
    client = _FakeStoreClient(error_status=500)
    timings = [({"status": 200, "body": ""}, 0.30), ({"status": 200, "body": ""}, 0.32), ({"status": 200, "body": ""}, 0.35)]
    with patch.object(cve_2026_102788, "HttpClient", return_value=client), patch.object(
        cve_2026_102788, "_timed_get", side_effect=timings
    ):
        result = cve_2026_102788.run_aggressive_probe("https://target.test", app=1, category=2)
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["sql_error"] is True
    assert result.evidence["order_column"] in result.detail


def test_gridbox_102788_time_probe_confirms_without_error_page():
    client = _FakeStoreClient(error_status=200)
    timings = [({"status": 200, "body": ""}, 0.30), ({"status": 200, "body": ""}, 0.32), ({"status": 200, "body": ""}, 2.30)]
    with patch.object(cve_2026_102788, "HttpClient", return_value=client), patch.object(
        cve_2026_102788, "_timed_get", side_effect=timings
    ):
        result = cve_2026_102788.run_aggressive_probe("https://target.test", app=1, category=2)
    assert result.status == "VULNERABLE"
    assert result.evidence["time_sqli"] is True
    assert result.evidence["sql_error"] is False


def test_gridbox_102788_patched_is_not_confirmed():
    client = _FakeStoreClient(error_status=200)
    timings = [({"status": 200, "body": ""}, 0.30), ({"status": 200, "body": ""}, 0.32), ({"status": 200, "body": ""}, 0.35)]
    with patch.object(cve_2026_102788, "HttpClient", return_value=client), patch.object(
        cve_2026_102788, "_timed_get", side_effect=timings
    ):
        result = cve_2026_102788.run_aggressive_probe("https://target.test", app=1, category=2)
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["sql_error"] is False
    assert result.evidence["time_sqli"] is False


def test_gridbox_102788_missing_store_is_blocked():
    client = _FakeStoreClient(page_body="<html><body>no store here</body></html>")
    with patch.object(cve_2026_102788, "HttpClient", return_value=client):
        result = cve_2026_102788.run_aggressive_probe("https://target.test")
    assert result.status == "BLOCKED_EXTERNAL"
    assert result.exploit_ran is False


def test_gridbox_102788_path_params_are_reused():
    client = _FakeStoreClient(error_status=500)
    timings = [({"status": 200, "body": ""}, 0.30), ({"status": 200, "body": ""}, 0.32), ({"status": 200, "body": ""}, 0.35)]
    with patch.object(cve_2026_102788, "HttpClient", return_value=client), patch.object(
        cve_2026_102788, "_timed_get", side_effect=timings
    ):
        result = cve_2026_102788.run_aggressive_probe(
            "https://target.test", path="/store?option=com_gridbox&view=blog&app=7&id=8"
        )
    assert result.status == "VULNERABLE"
    assert result.evidence["app_id"] == 7
    assert result.evidence["category_id"] == 8


def test_gridbox_102788_transport_error_is_reported():
    class _DownClient:
        def get(self, url: str, timeout: int | None = None) -> dict[str, object]:
            return {"status": 0, "error": {"type": "URLError", "message": "down"}}

    with patch.object(cve_2026_102788, "HttpClient", return_value=_DownClient()):
        result = cve_2026_102788.run_aggressive_probe("https://target.test", app=1, category=2)
    assert result.status == "ERROR"
