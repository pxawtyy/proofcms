from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_118495


class _FakeAcyClient:
    def __init__(self, key: str = "PROOFCMS118495KEY0123456789ABCDEF") -> None:
        self.key = key

    def request(self, url: str, method: str = "GET", headers=None, follow_redirects=True, timeout=None):
        location = f"http://target.test/index.php?proofcms118495={self.key}"
        return {"status": 303, "body": "", "headers": {"Location": location}}


class _PatchedAcyClient:
    def request(self, url: str, method: str = "GET", headers=None, follow_redirects=True, timeout=None):
        return {"status": 303, "body": "", "headers": {"Location": "http://target.test/index.php?proofcms118495={user:key}"}}


def test_acymailing_118495_version_boundaries():
    assert cve_2026_118495.classify_version("5.9.9") == "NOT_AFFECTED"
    assert cve_2026_118495.classify_version("6.0.0") == "LIKELY_VULNERABLE"
    assert cve_2026_118495.classify_version("11.0.5") == "LIKELY_VULNERABLE"
    assert cve_2026_118495.classify_version("11.1.1") == "LIKELY_VULNERABLE"
    assert cve_2026_118495.classify_version("11.1.2") == "NOT_AFFECTED"
    assert cve_2026_118495.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_acymailing_118495_leaked_key_confirms():
    with patch.object(cve_2026_118495, "HttpClient", return_value=_FakeAcyClient()):
        result = cve_2026_118495.run_aggressive_probe("https://target.test", "victim@example.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["leaked_key_length"] == 33
    assert result.evidence["key_matches_expected"] is None
    assert "PROOFCMS118495KEY" not in result.evidence["redirect_location"]


def test_acymailing_118495_expected_key_mismatch_is_not_confirmed():
    with patch.object(cve_2026_118495, "HttpClient", return_value=_FakeAcyClient()):
        result = cve_2026_118495.run_aggressive_probe(
            "https://target.test",
            "victim@example.test",
            expected_key="DIFFERENTKEY0123456789",
        )
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["key_matches_expected"] is False


def test_acymailing_118495_patched_leaves_tag_literal():
    with patch.object(cve_2026_118495, "HttpClient", return_value=_PatchedAcyClient()):
        result = cve_2026_118495.run_aggressive_probe("https://target.test", "victim@example.test")
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["leaked_key_length"] == 0


def test_acymailing_118495_aggressive_requires_email():
    result = cve_2026_118495.check(
        "https://target.test",
        run_exploit_check=True,
        exploit_mode="aggressive",
        plugins={"acymailing": {"found": True, "version": "11.0.5"}},
    )
    assert result.status == "BLOCKED_EXTERNAL"
    assert result.exploit_ran is False


def test_acymailing_118495_passive_reports_vulnerable_version():
    result = cve_2026_118495.passive_result({"acymailing": {"found": True, "version": "11.0.5"}})
    assert result.status == "LIKELY_VULNERABLE"


def test_acymailing_118495_passive_ignores_absent_component():
    result = cve_2026_118495.passive_result({"acymailing": {"found": False}})
    assert result.status == "NOT_DETECTED"
