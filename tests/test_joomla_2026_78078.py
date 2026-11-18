from __future__ import annotations

import re
from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_78078

TOKEN = "a" * 32


class _FakeHelixClient:
    def __init__(self, patched: bool = False) -> None:
        self.patched = patched
        self.uploaded = False
        self.marker = ""

    def get(self, url: str, timeout=None):
        if "com_users" in url or url.endswith("/index.php"):
            return {"status": 200, "body": f'"csrf.token":"{TOKEN}"'}
        if "images/proofcms-78078" in url:
            if self.patched:
                return {"status": 404, "body": ""}
            return {"status": 200, "body": self.marker}
        return {"status": 200, "body": ""}

    def request(self, url: str, method: str = "POST", headers=None, data=None, timeout=None, follow_redirects=True):
        if "user.login" in url:
            return {"status": 200, "body": "logout"}
        if "upload-media" in url:
            self.uploaded = True
            match = re.search(rb"PROOFCMS_78078_[a-f0-9]+", data or b"")
            self.marker = match.group(0).decode() if match else ""
            if self.patched:
                return {"status": 200, "body": '{"status":false,"message":"not an image"}'}
            return {"status": 200, "body": '{"status":true}'}
        return {"status": 200, "body": ""}


def test_helix_78078_version_boundaries():
    assert cve_2026_78078.classify_version("2.2.4") == "LIKELY_VULNERABLE"
    assert cve_2026_78078.classify_version("2.2.9") == "LIKELY_VULNERABLE"
    assert cve_2026_78078.classify_version("2.2.10") == "NOT_AFFECTED"
    assert cve_2026_78078.classify_version("2.2.11") == "NOT_AFFECTED"
    assert cve_2026_78078.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_helix_78078_spoofed_upload_is_confirmed():
    with patch.object(cve_2026_78078, "HttpClient", return_value=_FakeHelixClient()):
        result = cve_2026_78078.run_aggressive_probe(
            "https://target.test", username="admin", password="secret"
        )
    assert result.status == "VULNERABLE_UPLOAD_ONLY"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["marker_stored"] is True


def test_helix_78078_patched_rejects_non_image():
    with patch.object(cve_2026_78078, "HttpClient", return_value=_FakeHelixClient(patched=True)):
        result = cve_2026_78078.run_aggressive_probe(
            "https://target.test", username="admin", password="secret"
        )
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["marker_stored"] is False


def test_helix_78078_missing_credentials_is_blocked():
    result = cve_2026_78078.run_aggressive_probe("https://target.test")
    assert result.status == "BLOCKED_EXTERNAL"
    assert result.exploit_ran is False


def test_helix_78078_passive_reports_vulnerable_version():
    result = cve_2026_78078.passive_result({"helixultimate": {"found": True, "version": "2.2.4"}})
    assert result.status == "LIKELY_VULNERABLE"


def test_helix_78078_passive_ignores_absent_component():
    result = cve_2026_78078.passive_result({"helixultimate": {"found": False}})
    assert result.status == "NOT_DETECTED"
