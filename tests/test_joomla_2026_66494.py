from __future__ import annotations

import json
from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_66494


class _FakeShapesClient:
    def __init__(self, add_status: int = 201, list_status: int = 200, echo: bool = True) -> None:
        self.add_status = add_status
        self.list_status = list_status
        self.echo = echo
        self.shape = ""

    def request(self, url: str, method: str = "POST", headers=None, data=None, timeout=None, follow_redirects=False):
        if "addImageShapeAPI" in url:
            payload = json.loads((data or b"{}").decode())
            self.shape = payload.get("shape", "")
            if self.add_status >= 400:
                return {"status": self.add_status, "body": '{"success":false}'}
            return {"status": self.add_status, "body": '{"success":true,"data":{"id":7,"shape":"x"}}'}
        return {"status": self.list_status, "body": ""}

    def get(self, url: str, timeout=None):
        if self.list_status >= 400:
            return {"status": self.list_status, "body": '{"success":false}'}
        rows = [{"id": 7, "shape": self.shape}] if self.echo else []
        return {"status": self.list_status, "body": json.dumps({"success": True, "data": rows})}


def test_sppb_66494_version_boundaries():
    assert cve_2026_66494.classify_version("6.0.0") == "LIKELY_VULNERABLE"
    assert cve_2026_66494.classify_version("6.6.1") == "LIKELY_VULNERABLE"
    assert cve_2026_66494.classify_version("6.7.0") == "NOT_AFFECTED"
    assert cve_2026_66494.classify_version("6.10.0") == "NOT_AFFECTED"
    assert cve_2026_66494.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_sppb_66494_stored_marker_confirms():
    client = _FakeShapesClient()
    with patch.object(cve_2026_66494, "HttpClient", return_value=client):
        result = cve_2026_66494.run_aggressive_probe("https://target.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["retrieved"] is True
    assert result.evidence["add_status"] == 201


def test_sppb_66494_patched_endpoint_is_blocked():
    client = _FakeShapesClient(add_status=403, list_status=403)
    with patch.object(cve_2026_66494, "HttpClient", return_value=client):
        result = cve_2026_66494.run_aggressive_probe("https://target.test")
    assert result.status == "BLOCKED_EXTERNAL"
    assert result.evidence["retrieved"] is False


def test_sppb_66494_missing_marker_is_not_confirmed():
    client = _FakeShapesClient(echo=False)
    with patch.object(cve_2026_66494, "HttpClient", return_value=client):
        result = cve_2026_66494.run_aggressive_probe("https://target.test")
    assert result.status == "NOT_CONFIRMED"


def test_sppb_66494_passive_reports_vulnerable_version():
    result = cve_2026_66494.passive_result({"sppagebuilder": {"found": True, "version": "6.6.1"}})
    assert result.status == "LIKELY_VULNERABLE"


def test_sppb_66494_passive_ignores_absent_component():
    result = cve_2026_66494.passive_result({"sppagebuilder": {"found": False}})
    assert result.status == "NOT_DETECTED"
