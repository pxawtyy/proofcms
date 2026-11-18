from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_48941


class _FakeK2Client:
    def __init__(self, patched: bool = False, canary: bool = True) -> None:
        self.patched = patched
        self.canary = canary

    def get(self, url: str, timeout=None):
        if "canary.txt" in url:
            return {"status": 200 if self.canary else 404, "body": "canary"}
        if "task=checkin" in url:
            if self.patched:
                return {"status": 403, "body": "not authorised"}
            self.canary = False
            return {"status": 200, "body": ""}
        return {"status": 200, "body": ""}


def test_k2_48941_version_boundaries():
    assert cve_2026_48941.classify_version("2.8.0") == "LIKELY_VULNERABLE"
    assert cve_2026_48941.classify_version("2.26") == "LIKELY_VULNERABLE"
    assert cve_2026_48941.classify_version("2.27") == "NOT_AFFECTED"
    assert cve_2026_48941.classify_version("2.28") == "NOT_AFFECTED"
    assert cve_2026_48941.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_k2_48941_folder_delete_confirms():
    with patch.object(cve_2026_48941, "HttpClient", return_value=_FakeK2Client()):
        result = cve_2026_48941.run_aggressive_probe("https://target.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["canary_gone"] is True


def test_k2_48941_patched_guest_check_is_not_confirmed():
    with patch.object(cve_2026_48941, "HttpClient", return_value=_FakeK2Client(patched=True)):
        result = cve_2026_48941.run_aggressive_probe("https://target.test")
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["checkin_status"] == 403
    assert result.evidence["canary_gone"] is False


def test_k2_48941_missing_canary_is_blocked():
    with patch.object(cve_2026_48941, "HttpClient", return_value=_FakeK2Client(canary=False)):
        result = cve_2026_48941.run_aggressive_probe("https://target.test")
    assert result.status == "BLOCKED_EXTERNAL"
    assert result.exploit_ran is False


def test_k2_48941_passive_reports_vulnerable_version():
    result = cve_2026_48941.passive_result({"k2": {"found": True, "version": "2.8.0"}})
    assert result.status == "LIKELY_VULNERABLE"


def test_k2_48941_passive_ignores_absent_component():
    result = cve_2026_48941.passive_result({"k2": {"found": False}})
    assert result.status == "NOT_DETECTED"
