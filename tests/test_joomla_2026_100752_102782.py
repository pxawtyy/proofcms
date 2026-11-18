from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_100752, cve_2026_102782

MARKER_100752 = "PROOFCMS100752AABBCCDDEE"
MARKER_102782 = "PROOFCMS102782AABBCCDDEE"


class _FakeLeakClient:
    def __init__(self, body: str) -> None:
        self.body = body

    def request(self, url: str, method: str = "GET", headers=None, timeout=None):
        return {"status": 500, "body": self.body}

    def get(self, url: str, timeout=None):
        return {"status": 200, "body": "component"}


def test_rem_100752_version_boundaries():
    assert cve_2026_100752.classify_version("6.7.8") == "LIKELY_VULNERABLE"
    assert cve_2026_100752.classify_version("6.7.9") == "NOT_AFFECTED"
    assert cve_2026_100752.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_rem_100752_marker_confirms():
    with patch.object(cve_2026_100752, "HttpClient", return_value=_FakeLeakClient(f"~{MARKER_100752}~")), patch.object(
        cve_2026_100752.secrets, "token_hex", return_value="aabbccddee"
    ):
        result = cve_2026_100752.run_aggressive_probe("https://target.test")
    assert result.status == "VULNERABLE"
    assert result.evidence["leaked"] is True


def test_rem_100752_no_marker_not_confirmed():
    with patch.object(cve_2026_100752, "HttpClient", return_value=_FakeLeakClient("normal page")), patch.object(
        cve_2026_100752.secrets, "token_hex", return_value="aabbccddee"
    ):
        result = cve_2026_100752.run_aggressive_probe("https://target.test")
    assert result.status == "NOT_CONFIRMED"


def test_simplemembership_102782_version_boundaries():
    assert cve_2026_102782.classify_version("7.3.9") == "LIKELY_VULNERABLE"
    assert cve_2026_102782.classify_version("7.4.0") == "NOT_AFFECTED"
    assert cve_2026_102782.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_simplemembership_102782_marker_confirms():
    with patch.object(cve_2026_102782, "HttpClient", return_value=_FakeLeakClient(f"~{MARKER_102782}~")), patch.object(
        cve_2026_102782.secrets, "token_hex", return_value="aabbccddee"
    ):
        result = cve_2026_102782.run_aggressive_probe("https://target.test")
    assert result.status == "VULNERABLE"
    assert result.evidence["leaked"] is True


def test_simplemembership_102782_no_marker_not_confirmed():
    with patch.object(cve_2026_102782, "HttpClient", return_value=_FakeLeakClient("invalid login")), patch.object(
        cve_2026_102782.secrets, "token_hex", return_value="aabbccddee"
    ):
        result = cve_2026_102782.run_aggressive_probe("https://target.test")
    assert result.status == "NOT_CONFIRMED"
