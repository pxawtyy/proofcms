from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_57828

TOKEN = "a" * 32
MARKER = "PROOFCMS_57828_AABBCCDDEEFF"


class _FakePhocaClient:
    def __init__(self, executed: bool = True) -> None:
        self.executed = executed

    def get(self, url: str, timeout=None):
        if "view=login" in url or "view=user" in url:
            return {"status": 200, "body": f'name="{TOKEN}" value="1"'}
        if self.executed:
            return {"status": 200, "body": MARKER}
        return {"status": 404, "body": "not found"}

    def request(self, url: str, method: str = "GET", headers=None, data=None, timeout=None):
        if "user.login" in url:
            return {"status": 200, "body": "logout"}
        if self.executed:
            return {"status": 200, "body": "File uploaded"}
        return {"status": 200, "body": "The file type is not allowed - file cannot be uploaded"}


def test_phoca_57828_version_boundaries():
    assert cve_2026_57828.classify_version("6.1.2") == "LIKELY_VULNERABLE"
    assert cve_2026_57828.classify_version("5.0.0") == "LIKELY_VULNERABLE"
    assert cve_2026_57828.classify_version("6.1.3") == "NOT_AFFECTED"
    assert cve_2026_57828.classify_version("6.2.0") == "NOT_AFFECTED"
    assert cve_2026_57828.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_phoca_57828_executed_marker_confirms():
    with patch.object(cve_2026_57828, "HttpClient", return_value=_FakePhocaClient()), patch.object(
        cve_2026_57828, "_frontend_login", return_value=True
    ), patch.object(cve_2026_57828.secrets, "token_hex", side_effect=["aabbccddeeff", "11223344"]):
        result = cve_2026_57828.run_aggressive_probe(
            "https://target.test",
            username="uploader",
            password="secret",
            catid=1,
        )
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["marker_executed"] is True


def test_phoca_57828_patched_rejects_upload():
    with patch.object(cve_2026_57828, "HttpClient", return_value=_FakePhocaClient(executed=False)), patch.object(
        cve_2026_57828, "_frontend_login", return_value=True
    ), patch.object(cve_2026_57828.secrets, "token_hex", side_effect=["aabbccddeeff", "11223344"]):
        result = cve_2026_57828.run_aggressive_probe(
            "https://target.test",
            username="uploader",
            password="secret",
            catid=1,
        )
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["upload_rejected"] is True


def test_phoca_57828_requires_credentials():
    result = cve_2026_57828.run_aggressive_probe("https://target.test")
    assert result.status == "BLOCKED_EXTERNAL"
    assert result.exploit_ran is False


def test_phoca_57828_passive_reports_vulnerable_version():
    result = cve_2026_57828.passive_result({"phocadownload": {"found": True, "version": "6.1.2"}})
    assert result.status == "LIKELY_VULNERABLE"


def test_phoca_57828_passive_ignores_absent_component():
    result = cve_2026_57828.passive_result({"phocadownload": {"found": False}})
    assert result.status == "NOT_DETECTED"
