from __future__ import annotations

import json
from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_81565

TOKEN = "a" * 32
MARKER = "PROOFCMS_81565_AABBCCDD"


class _FakeSppbClient:
    def __init__(self, accepted: bool = True) -> None:
        self.accepted = accepted

    def get(self, url: str, timeout=None):
        if "administrator/index.php" in url and "task=" not in url:
            return {"status": 200, "body": f'name="{TOKEN}" value="1"'}
        if self.accepted:
            return {"status": 200, "body": MARKER}
        return {"status": 404, "body": "not found"}

    def request(self, url: str, method: str = "GET", headers=None, data=None, timeout=None):
        if "task=editor.media" in url:
            if self.accepted:
                return {"status": 200, "body": json.dumps({"data": {"status": True, "path": "tmp/proofcms-81565-aabbccdd.json"}})}
            return {"status": 200, "body": json.dumps({"data": {"status": False, "message": "Upload failed"}})}
        return {"status": 200, "body": "ok"}


def test_sppb_81565_version_boundaries():
    assert cve_2026_81565.classify_version("3.9.9") == "NOT_AFFECTED"
    assert cve_2026_81565.classify_version("4.0.0") == "LIKELY_VULNERABLE"
    assert cve_2026_81565.classify_version("6.0.0") == "LIKELY_VULNERABLE"
    assert cve_2026_81565.classify_version("6.9.0") == "LIKELY_VULNERABLE"
    assert cve_2026_81565.classify_version("6.9.1") == "NOT_AFFECTED"
    assert cve_2026_81565.classify_version("6.10.0") == "NOT_AFFECTED"
    assert cve_2026_81565.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_sppb_81565_upload_to_tmp_confirms():
    with patch.object(cve_2026_81565, "HttpClient", return_value=_FakeSppbClient()), patch.object(
        cve_2026_81565, "_admin_login", return_value=TOKEN
    ), patch.object(cve_2026_81565.secrets, "token_hex", return_value="aabbccdd"):
        result = cve_2026_81565.run_aggressive_probe(
            "https://target.test", username="admin", password="secret"
        )
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["marker_served"] is True
    assert result.evidence["folder"] == "tmp"


def test_sppb_81565_patched_rejects_upload():
    with patch.object(cve_2026_81565, "HttpClient", return_value=_FakeSppbClient(accepted=False)), patch.object(
        cve_2026_81565, "_admin_login", return_value=TOKEN
    ), patch.object(cve_2026_81565.secrets, "token_hex", return_value="aabbccdd"):
        result = cve_2026_81565.run_aggressive_probe(
            "https://target.test", username="admin", password="secret"
        )
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["upload_accepted"] is False


def test_sppb_81565_requires_credentials():
    result = cve_2026_81565.run_aggressive_probe("https://target.test")
    assert result.status == "BLOCKED_EXTERNAL"
    assert result.exploit_ran is False


def test_sppb_81565_passive_reports_vulnerable_version():
    result = cve_2026_81565.passive_result({"sppagebuilder": {"found": True, "version": "6.0.0"}})
    assert result.status == "LIKELY_VULNERABLE"
