from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_117543


class _FakeJdClient:
    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self.body = body

    def request(self, url: str, method: str = "GET", headers=None, data=None, timeout=None, follow_redirects=True):
        return {"status": self.status, "body": self.body}

    def get(self, url: str, timeout=None):
        return {"status": self.status, "body": self.body}


def test_jdownloads_117543_version_boundaries():
    assert cve_2026_117543.classify_version("4.0.0") == "LIKELY_VULNERABLE"
    assert cve_2026_117543.classify_version("4.1.7") == "LIKELY_VULNERABLE"
    assert cve_2026_117543.classify_version("4.1.8") == "NOT_AFFECTED"
    assert cve_2026_117543.classify_version("4.2.0") == "NOT_AFFECTED"
    assert cve_2026_117543.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_jdownloads_117543_canary_confirms():
    with patch.object(cve_2026_117543, "HttpClient", return_value=_FakeJdClient(200, "PROOFCMS_SSRF_CANARY_MARKER")):
        result = cve_2026_117543.run_aggressive_probe("https://target.test", download_id=1, catid=2)
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["marker_found"] is True


def test_jdownloads_117543_redirect_is_not_confirmed():
    with patch.object(cve_2026_117543, "HttpClient", return_value=_FakeJdClient(303, "")):
        result = cve_2026_117543.run_aggressive_probe("https://target.test", download_id=1, catid=2)
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["status"] == 303


def test_jdownloads_117543_missing_download_is_blocked():
    with patch.object(cve_2026_117543, "HttpClient", return_value=_FakeJdClient(404, "")):
        result = cve_2026_117543.run_aggressive_probe("https://target.test", download_id=1, catid=2)
    assert result.status == "BLOCKED_EXTERNAL"


def test_jdownloads_117543_passive_reports_vulnerable_version():
    result = cve_2026_117543.passive_result({"jdownloads": {"found": True, "version": "4.1.7"}})
    assert result.status == "LIKELY_VULNERABLE"


def test_jdownloads_117543_passive_ignores_absent_component():
    result = cve_2026_117543.passive_result({"jdownloads": {"found": False}})
    assert result.status == "NOT_DETECTED"
