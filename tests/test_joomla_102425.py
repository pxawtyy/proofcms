from __future__ import annotations

import re
from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_102425


class _FakeBaFormsClient:
    def __init__(self, execute: bool = True, home_token: str | None = "a" * 32, legacy_token: str | None = None) -> None:
        self.execute = execute
        self.home_token = home_token
        self.legacy_token = legacy_token

    def get(self, url: str, timeout: int | None = None) -> dict[str, object]:
        if "getSessionToken" in url:
            return {"status": 200, "body": self.legacy_token or ""}
        body = ""
        if self.home_token:
            body = f'<script type="application/json">{{"csrf.token":"{self.home_token}"}}</script>'
        return {"status": 200, "body": body}

    def request(self, url: str, method: str = "POST", headers=None, data=None, timeout=None):
        text = data.decode("utf-8", "ignore") if isinstance(data, bytes) else str(data or "")
        match = re.search(r"PROOFCMS_BAFORMS_RCE_[a-f0-9]+", text)
        marker = match.group(0) if match else ""
        if self.execute:
            return {"status": 200, "body": marker + '{"status":true,"message":"ProofCMS ok"}'}
        return {"status": 200, "body": '{"status":true,"message":"ProofCMS ok"}'}


def test_baforms_102425_version_boundaries():
    assert cve_2026_102425.classify_version("2.4.0") == "LIKELY_VULNERABLE"
    assert cve_2026_102425.classify_version("2.4.3.1") == "LIKELY_VULNERABLE"
    assert cve_2026_102425.classify_version("2.4.3.3") == "LIKELY_VULNERABLE"
    assert cve_2026_102425.classify_version("2.4.3.4") == "NOT_AFFECTED"
    assert cve_2026_102425.classify_version("2.4.4.0") == "NOT_AFFECTED"
    assert cve_2026_102425.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_baforms_102425_shortcode_breakout_confirms():
    client = _FakeBaFormsClient(execute=True)
    with patch.object(cve_2026_102425, "HttpClient", return_value=client):
        result = cve_2026_102425.run_aggressive_probe("https://target.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["marker_executed"] is True
    assert result.evidence["token_found"] is True


def test_baforms_102425_patched_control_is_not_confirmed():
    client = _FakeBaFormsClient(execute=False)
    with patch.object(cve_2026_102425, "HttpClient", return_value=client):
        result = cve_2026_102425.run_aggressive_probe("https://target.test")
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["marker_executed"] is False


def test_baforms_102425_missing_token_is_blocked():
    client = _FakeBaFormsClient(home_token=None)
    with patch.object(cve_2026_102425, "HttpClient", return_value=client):
        result = cve_2026_102425.run_aggressive_probe("https://target.test")
    assert result.status == "BLOCKED_EXTERNAL"
    assert result.exploit_ran is False


def test_baforms_102425_legacy_token_endpoint():
    client = _FakeBaFormsClient(home_token=None, legacy_token="b" * 32)
    with patch.object(cve_2026_102425, "HttpClient", return_value=client):
        result = cve_2026_102425.run_aggressive_probe("https://target.test")
    assert result.status == "VULNERABLE"
    assert result.evidence["token_found"] is True


def test_baforms_102425_transport_error_is_reported():
    class _DownClient:
        def get(self, url: str, timeout: int | None = None) -> dict[str, object]:
            return {"status": 0, "error": {"type": "URLError", "message": "down"}}

        def request(self, url: str, method: str = "POST", headers=None, data=None, timeout=None):
            return {"status": 0, "error": {"type": "URLError", "message": "down"}}

    with patch.object(cve_2026_102425, "HttpClient", return_value=_DownClient()):
        result = cve_2026_102425.run_aggressive_probe("https://target.test")
    assert result.status == "BLOCKED_EXTERNAL"
