from __future__ import annotations

import re
from unittest.mock import patch
from urllib.parse import parse_qs

from proofcms.modules.joomla import cve_2025_30085


class _FakeRsformClient:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.marker = ""
        self.filename = ""
        self.payload = ""

    def request(self, url: str, method: str = "POST", headers=None, data=None, timeout=None, follow_redirects=False):
        if "exporttask" in url:
            fields = parse_qs((data or b"").decode())
            for key in fields:
                if key.startswith("ExportSubmission[") and key.endswith("]"):
                    self.payload = key[len("ExportSubmission[") : -1]
                    match = re.search(r"PROOFCMS_RSFORM_RCE_[a-f0-9]+", self.payload)
                    self.marker = match.group(0) if match else ""
            self.filename = fields.get("ExportFile", [""])[0].rsplit("/", 1)[-1]
            return {"status": 200, "body": "export form"}
        return {"status": 200, "body": "END"}

    def get(self, url: str, timeout=None):
        if self.mode == "executed":
            return {"status": 200, "body": self.marker}
        if self.mode == "stored":
            return {"status": 200, "body": self.payload}
        return {"status": 404, "body": ""}


def test_rsform_30085_version_boundaries():
    assert cve_2025_30085.classify_version("3.0.0") == "LIKELY_VULNERABLE"
    assert cve_2025_30085.classify_version("3.1.11") == "LIKELY_VULNERABLE"
    assert cve_2025_30085.classify_version("3.3.14") == "LIKELY_VULNERABLE"
    assert cve_2025_30085.classify_version("3.3.15") == "NOT_AFFECTED"
    assert cve_2025_30085.classify_version("3.4.6") == "NOT_AFFECTED"
    assert cve_2025_30085.classify_version("2.9.0") == "NOT_AFFECTED"
    assert cve_2025_30085.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_rsform_30085_executed_marker_confirms():
    client = _FakeRsformClient("executed")
    with patch.object(cve_2025_30085, "HttpClient", return_value=client), patch.object(
        cve_2025_30085, "joomla_admin_login", return_value=True
    ):
        result = cve_2025_30085.run_aggressive_probe(
            "https://target.test", username="admin", password="secret"
        )
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["marker_executed"] is True


def test_rsform_30085_stored_payload_is_upload_only():
    client = _FakeRsformClient("stored")
    with patch.object(cve_2025_30085, "HttpClient", return_value=client), patch.object(
        cve_2025_30085, "joomla_admin_login", return_value=True
    ):
        result = cve_2025_30085.run_aggressive_probe(
            "https://target.test", username="admin", password="secret"
        )
    assert result.status == "VULNERABLE_UPLOAD_ONLY"
    assert result.evidence["marker_stored"] is True


def test_rsform_30085_patched_export_is_not_confirmed():
    client = _FakeRsformClient("missing")
    with patch.object(cve_2025_30085, "HttpClient", return_value=client), patch.object(
        cve_2025_30085, "joomla_admin_login", return_value=True
    ):
        result = cve_2025_30085.run_aggressive_probe(
            "https://target.test", username="admin", password="secret"
        )
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["file_status"] == 404


def test_rsform_30085_missing_credentials_is_blocked():
    result = cve_2025_30085.run_aggressive_probe("https://target.test")
    assert result.status == "BLOCKED_EXTERNAL"
    assert result.exploit_ran is False


def test_rsform_30085_failed_login_is_not_confirmed():
    with patch.object(cve_2025_30085, "HttpClient", return_value=_FakeRsformClient("executed")), patch.object(
        cve_2025_30085, "joomla_admin_login", return_value=False
    ):
        result = cve_2025_30085.run_aggressive_probe(
            "https://target.test", username="admin", password="wrong"
        )
    assert result.status == "NOT_CONFIRMED"


def test_rsform_30085_passive_reports_vulnerable_version():
    result = cve_2025_30085.passive_result({"rsform": {"found": True, "version": "3.1.11"}})
    assert result.status == "LIKELY_VULNERABLE"
    assert result.exploit_available is True


def test_rsform_30085_passive_ignores_absent_component():
    result = cve_2025_30085.passive_result({"rsform": {"found": False}})
    assert result.status == "NOT_DETECTED"
