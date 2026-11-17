from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_48906

TOKEN = "a" * 32


class _FakeTassosClient:
    def __init__(self, patched: bool = False, token: bool = True) -> None:
        self.patched = patched
        self.token = token
        self.deleted = False

    def get(self, url: str, timeout=None):
        if "proofcms-delete-canary" in url:
            return {"status": 404 if self.deleted else 200, "body": "canary"}
        if self.token:
            return {"status": 200, "body": f'<input name="{TOKEN}" value="1">'}
        return {"status": 200, "body": ""}

    def request(self, url: str, method: str = "POST", headers=None, data=None, timeout=None, follow_redirects=True):
        if self.patched:
            return {"status": 400, "body": "MISSING_HANDLER"}
        self.deleted = True
        return {"status": 200, "body": '{"error":false,"response":"File deleted."}'}


def test_tassos_48906_version_boundaries():
    assert cve_2026_48906.classify_version("6.0.15") == "LIKELY_VULNERABLE"
    assert cve_2026_48906.classify_version("6.0.37") == "LIKELY_VULNERABLE"
    assert cve_2026_48906.classify_version("6.1.0") == "NOT_AFFECTED"
    assert cve_2026_48906.classify_version("6.1.51") == "NOT_AFFECTED"
    assert cve_2026_48906.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_tassos_48906_canary_deleted_confirms():
    with patch.object(cve_2026_48906, "HttpClient", return_value=_FakeTassosClient()):
        result = cve_2026_48906.run_aggressive_probe("https://target.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["canary_gone"] is True
    assert result.evidence["deleted_json"] is True


def test_tassos_48906_patched_handler_is_not_confirmed():
    with patch.object(cve_2026_48906, "HttpClient", return_value=_FakeTassosClient(patched=True)):
        result = cve_2026_48906.run_aggressive_probe("https://target.test")
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["canary_gone"] is False


def test_tassos_48906_missing_token_is_blocked():
    with patch.object(cve_2026_48906, "HttpClient", return_value=_FakeTassosClient(token=False)):
        result = cve_2026_48906.run_aggressive_probe("https://target.test")
    assert result.status == "BLOCKED_EXTERNAL"
    assert result.exploit_ran is False


def test_tassos_48906_passive_reports_vulnerable_version():
    result = cve_2026_48906.passive_result({"nrframework": {"found": True, "version": "6.0.15"}})
    assert result.status == "LIKELY_VULNERABLE"


def test_tassos_48906_passive_ignores_absent_component():
    result = cve_2026_48906.passive_result({"nrframework": {"found": False}})
    assert result.status == "NOT_DETECTED"
