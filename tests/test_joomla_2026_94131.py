from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_94131


class _FakeAcyClient:
    def __init__(self, patched: bool = False, canary: bool = True) -> None:
        self.patched = patched
        self.canary = canary
        self.calls = 0

    def get(self, url: str, timeout=None):
        return {"status": 200 if self.canary else 404, "body": "canary"}

    def request(self, url: str, method: str = "POST", headers=None, data=None, timeout=None, follow_redirects=True):
        self.calls += 1
        if self.calls == 2 and not self.patched:
            self.canary = False
        return {"status": 200, "body": '{"message":"ok"}'}


def test_acymailing_94131_version_boundaries():
    assert cve_2026_94131.classify_version("11.0.5") == "LIKELY_VULNERABLE"
    assert cve_2026_94131.classify_version("11.0.9") == "LIKELY_VULNERABLE"
    assert cve_2026_94131.classify_version("11.1.0") == "NOT_AFFECTED"
    assert cve_2026_94131.classify_version("11.1.1") == "NOT_AFFECTED"
    assert cve_2026_94131.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_acymailing_94131_canary_deleted_confirms():
    with patch.object(cve_2026_94131, "HttpClient", return_value=_FakeAcyClient()):
        result = cve_2026_94131.run_aggressive_probe("https://target.test", field_id=1)
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["canary_gone"] is True


def test_acymailing_94131_patched_keeps_canary():
    with patch.object(cve_2026_94131, "HttpClient", return_value=_FakeAcyClient(patched=True)):
        result = cve_2026_94131.run_aggressive_probe("https://target.test", field_id=1)
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["canary_gone"] is False


def test_acymailing_94131_missing_canary_is_blocked():
    with patch.object(cve_2026_94131, "HttpClient", return_value=_FakeAcyClient(canary=False)):
        result = cve_2026_94131.run_aggressive_probe("https://target.test", field_id=1)
    assert result.status == "BLOCKED_EXTERNAL"
    assert result.exploit_ran is False


def test_acymailing_94131_passive_reports_vulnerable_version():
    result = cve_2026_94131.passive_result({"acymailing": {"found": True, "version": "11.0.5"}})
    assert result.status == "LIKELY_VULNERABLE"


def test_acymailing_94131_passive_ignores_absent_component():
    result = cve_2026_94131.passive_result({"acymailing": {"found": False}})
    assert result.status == "NOT_DETECTED"
