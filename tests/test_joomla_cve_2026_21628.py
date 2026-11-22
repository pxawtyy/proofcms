from __future__ import annotations

import re
from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_21628 as astroid


class _FakeClient:
    def __init__(self, mode: str = "vuln", token: bool = True) -> None:
        self.mode = mode
        self.token = token
        self.renamed = False
        self.removed = False
        self.marker = "PROOFCMS_none"
        self.transcript: list[dict] = []

    def get(self, url: str, headers=None, timeout: int | None = None) -> dict[str, object]:
        if url.endswith("/administrator/"):
            if not self.token:
                return {"status": 200, "body": "<html>login</html>"}
            return {
                "status": 200,
                "body": '<input type="hidden" name="' + ("a" * 32) + '" value="1">',
            }
        if "/images/" in url and url.endswith(".php"):
            if self.removed:
                return {"status": 404, "body": "not found"}
            if self.renamed and self.mode == "vuln":
                return {"status": 200, "body": self.marker}
            return {"status": 404, "body": "not found"}
        return {"status": 404, "body": ""}

    def post_multipart(
        self,
        url: str,
        fields: dict | None = None,
        files: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
    ) -> dict[str, object]:
        if self.mode == "transport":
            return {"status": 0, "error": {"type": "TransportError", "message": "boom"}}
        if self.mode == "patched":
            return {
                "status": 403,
                "body": '{"status":"error","code":403,"message":"You are not authorized to access this page."}',
            }
        payload = b""
        if files and "file" in files:
            payload = files["file"][1]
        match = re.search(rb"PROOFCMS_[0-9a-f]+", payload)
        if match:
            self.marker = match.group(0).decode()
        return {
            "status": 200,
            "body": '{"status":"success","code":200,"data":{"filename":"proofcms.svg","folder":""}}',
        }

    def post(
        self,
        url: str,
        data=None,
        fields=None,
        files=None,
        headers=None,
        timeout: int | None = None,
    ) -> dict[str, object]:
        if "action=rename" in url:
            self.renamed = True
            return {"status": 200, "body": '{"status":"success","code":200,"data":{"message":"renamed"}}'}
        if "action=remove" in url:
            self.removed = True
            return {"status": 200, "body": '{"status":"success","code":200,"data":{"message":"removed"}}'}
        return {"status": 200, "body": "{}"}


def _probe(fake: _FakeClient):
    with patch.object(astroid, "HttpClient", return_value=fake):
        return astroid.run_safe_probe("http://127.0.0.1:9217")


def test_21628_classify():
    assert astroid._classify("1.9.9") == "NOT_AFFECTED"
    assert astroid._classify("2.0.0") == "LIKELY_VULNERABLE"
    assert astroid._classify("3.3.10") == "LIKELY_VULNERABLE"
    assert astroid._classify("3.3.11") == "PATCHED"
    assert astroid._classify("3.3.12") == "PATCHED"
    assert astroid._classify(None) == "INCONCLUSIVE"


def test_21628_passive():
    vulnerable = astroid.check(
        "http://127.0.0.1:9217",
        plugins={"astroid": {"found": True, "version": "3.3.10"}},
    )
    assert vulnerable.status == "LIKELY_VULNERABLE"
    assert vulnerable.component_version == "3.3.10"

    patched = astroid.check(
        "http://127.0.0.1:9217",
        plugins={"astroid": {"found": True, "version": "3.3.11"}},
    )
    assert patched.status == "PATCHED"

    missing = astroid.check("http://127.0.0.1:9217", plugins={})
    assert missing.status == "NOT_DETECTED"


def test_21628_vulnerable_marker_confirms():
    fake = _FakeClient(mode="vuln")
    result = _probe(fake)
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["marker_found"] is True
    assert result.evidence["cleanup_verified"] is True
    assert result.uploaded_filename is None


def test_21628_patched_403_is_not_confirmed():
    fake = _FakeClient(mode="patched")
    result = _probe(fake)
    assert result.status == "NOT_CONFIRMED"
    assert "not authorized" in result.evidence["upload_response"]


def test_21628_missing_token_is_not_confirmed():
    fake = _FakeClient(token=False)
    result = _probe(fake)
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["token_accepted"] is False


def test_21628_transport_is_error():
    fake = _FakeClient(mode="transport")
    result = _probe(fake)
    assert result.status == "ERROR"
    assert result.confidence == "LOW"


def test_21628_check_safe_and_gate():
    with patch.object(astroid, "HttpClient", return_value=_FakeClient(mode="vuln")):
        result = astroid.check(
            "http://127.0.0.1:9217",
            plugins={"astroid": {"found": True, "version": "3.3.10"}},
            run_exploit_check=True,
            exploit_mode="safe",
        )
    assert result.status == "VULNERABLE"

    aggressive = astroid.check(
        "http://127.0.0.1:9217",
        plugins={"astroid": {"found": True, "version": "3.3.10"}},
        run_exploit_check=True,
        exploit_mode="aggressive",
    )
    assert aggressive.status == "LIKELY_VULNERABLE"
    assert "self-cleaning PHP-marker" in aggressive.detail

    patched = astroid.check(
        "http://127.0.0.1:9217",
        plugins={"astroid": {"found": True, "version": "3.3.11"}},
        run_exploit_check=True,
        exploit_mode="safe",
    )
    assert patched.status == "PATCHED"


def test_21628_metadata_contract():
    meta = astroid.metadata()
    assert meta["cve"] == "CVE-2026-21628"
    assert meta["cms"] == "joomla"
    assert meta["exploit_modes"] == ["safe"]
    assert meta["required_detectors"] == ["astroid"]
    assert "3.3.11" in meta["affected_rule"]
