from __future__ import annotations

import base64
import re
from typing import Any
from unittest.mock import patch
from urllib.parse import parse_qs, unquote

from proofcms.modules.joomla import (
    cve_2026_65766,
    cve_2026_65876,
    cve_2026_65879,
    cve_2026_65880,
    cve_2026_67285,
)

TOKEN = "a" * 32


class _DummyClient:
    def __init__(self, *args, **kwargs) -> None:
        pass

    def get(self, url: str, timeout: int | None = None) -> dict[str, object]:
        return {"status": 200, "body": ""}

    def request(self, url: str, method: str = "POST", headers=None, data=None, timeout=None, follow_redirects=False):
        return {"status": 200, "body": ""}


# --- CVE-2026-65880 -------------------------------------------------------


class _FakeSignatureClient:
    def __init__(self, stored: bool, execute: bool = False) -> None:
        self.stored = stored
        self.execute = execute
        self.marker = ""
        self.base = ""

    def get(self, url: str, timeout: int | None = None) -> dict[str, object]:
        if url.endswith("/index.php"):
            return {"status": 200, "body": '<script>{"csrf.token":"' + TOKEN + '"}</script>'}
        if self.stored and self.marker:
            payload = f'<?php echo "{self.marker}"; ?>'
            if self.execute:
                return {"status": 200, "body": self.marker}
            return {"status": 200, "body": payload}
        return {"status": 404, "body": ""}

    def request(self, url: str, method: str = "POST", headers=None, data=None, timeout=None, follow_redirects=False):
        fields = parse_qs((data or b"").decode())
        raw = unquote(fields.get("5", [""])[0])
        match = re.search(r"PROOFCMS_BAFORMS_SIG_[a-f0-9]+", base64.b64decode(raw.split(",", 1)[-1]).decode())
        self.marker = match.group(0) if match else ""
        if self.stored:
            return {"status": 200, "body": f'<img src="{self.base}/images/baforms/signatures/form-3/x.jpg">'}
        return {"status": 200, "body": f'<img src="{self.base}/">'}


def test_baforms_65880_version_boundaries():
    assert cve_2026_65880.classify_version("2.4.3.1") == "LIKELY_VULNERABLE"
    assert cve_2026_65880.classify_version("2.4.2") == "LIKELY_VULNERABLE"
    assert cve_2026_65880.classify_version("2.4.3.2") == "NOT_AFFECTED"
    assert cve_2026_65880.classify_version("2.4.4.0") == "NOT_AFFECTED"
    assert cve_2026_65880.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_baforms_65880_stored_payload_is_upload_only():
    client = _FakeSignatureClient(stored=True)
    client.base = "https://target.test"
    with patch.object(cve_2026_65880, "HttpClient", return_value=client):
        result = cve_2026_65880.run_aggressive_probe("https://target.test")
    assert result.status == "VULNERABLE_UPLOAD_ONLY"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["marker_stored"] is True
    assert result.evidence["marker_executed"] is False


def test_baforms_65880_executed_payload_is_vulnerable():
    client = _FakeSignatureClient(stored=True, execute=True)
    client.base = "https://target.test"
    with patch.object(cve_2026_65880, "HttpClient", return_value=client):
        result = cve_2026_65880.run_aggressive_probe("https://target.test")
    assert result.status == "VULNERABLE"


def test_baforms_65880_patched_rejects_image():
    client = _FakeSignatureClient(stored=False)
    client.base = "https://target.test"
    with patch.object(cve_2026_65880, "HttpClient", return_value=client):
        result = cve_2026_65880.run_aggressive_probe("https://target.test")
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["marker_stored"] is False


# --- CVE-2026-65879 -------------------------------------------------------


def test_sppb_65879_version_boundaries():
    assert cve_2026_65879.classify_version("6.6.1") == "LIKELY_VULNERABLE"
    assert cve_2026_65879.classify_version("6.7.0") == "LIKELY_VULNERABLE"
    assert cve_2026_65879.classify_version("6.7.1") == "NOT_AFFECTED"
    assert cve_2026_65879.classify_version("6.9.0") == "NOT_AFFECTED"
    assert cve_2026_65879.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_sppb_65879_passive_reports_vulnerable_version():
    result = cve_2026_65879.passive_result({"sppagebuilder": {"found": True, "version": "6.7.0"}})
    assert result.status == "LIKELY_VULNERABLE"
    assert result.exploit_available is True


def test_sppb_65879_passive_ignores_absent_component():
    result = cve_2026_65879.passive_result({"sppagebuilder": {"found": False}})
    assert result.status == "NOT_DETECTED"


class _FakeMailClient:
    def __init__(self, accepted: bool) -> None:
        self.accepted = accepted

    def get(self, url: str, headers=None, timeout: int | None = None) -> dict[str, object]:
        return {"status": 200, "body": f'<input name="{TOKEN}" value="1">'}

    def request(self, url: str, method: str = "POST", headers=None, data=None, timeout=None, follow_redirects=True):
        payload = '{"status":true,"content":"Email sent successfully!"}' if self.accepted else '{"status":false,"content":"Restricted Access"}'
        return {"status": 200, "body": '{"success":true,"data":' + __import__("json").dumps(payload) + '}'}


def test_sppb_65879_forged_mail_is_confirmed():
    result = cve_2026_65879.forge_form_id("attacker@example.test", "spoofed@example.test")
    assert result.count(":") == 1
    assert len(result.split(":")[1]) == 32
    with patch.object(cve_2026_65879, "HttpClient", return_value=_FakeMailClient(True)):
        finding = cve_2026_65879.run_aggressive_probe("https://target.test")
    assert finding.status == "VULNERABLE"
    assert finding.confidence == "CONFIRMED"
    assert finding.evidence["recipient"] == "attacker@example.test"


def test_sppb_65879_rejected_forgery_is_not_affected():
    with patch.object(cve_2026_65879, "HttpClient", return_value=_FakeMailClient(False)):
        finding = cve_2026_65879.run_aggressive_probe("https://target.test")
    assert finding.status == "NOT_AFFECTED"


# --- CVE-2026-67285 -------------------------------------------------------


class _FakeSppbEditorClient:
    """Simulates the site login and the addon-preview JSON view."""

    def __init__(self, include_marker: bool = True, benign_ok: bool = True) -> None:
        self.include_marker = include_marker
        self.benign_ok = benign_ok

    def get(self, url: str, timeout: int | None = None) -> dict[str, object]:
        if "view=login" in url:
            return {"status": 200, "body": f'<input name="{TOKEN}" value="1">'}
        if url.endswith("/index.php"):
            return {"status": 200, "body": f'<input name="{TOKEN}" value="1"> Logout'}
        if "task=ajax" in url:
            return {"status": 200, "body": "PROOFCMS_LFI_MARKER" if self.include_marker else "no marker"}
        return {"status": 200, "body": ""}

    def request(self, url: str, method: str = "POST", headers=None, data=None, timeout=None, follow_redirects=False):
        fields = parse_qs((data or b"").decode())
        if "user.login" in url:
            return {
                "status": 303,
                "headers": {"Location": "/index.php/component/users/profile"},
                "body": "",
            }
        name = fields.get("addon[name]", [""])[0]
        if name == cve_2026_67285.BENIGN_ADDON:
            body = '<div class="sppb-addon-wrapper">ok</div>' if self.benign_ok else '{"error":true}'
            return {"status": 200, "body": body}
        body = "PROOFCMS_LFI_MARKER" if self.include_marker else '<div class="sppb-addon-wrapper">no marker</div>'
        return {"status": 200, "body": body}


def test_sppb_67285_version_boundaries():
    assert cve_2026_67285.classify_version("6.7.0") == "LIKELY_VULNERABLE"
    assert cve_2026_67285.classify_version("6.0.0") == "LIKELY_VULNERABLE"
    assert cve_2026_67285.classify_version("6.8.0") == "NOT_AFFECTED"
    assert cve_2026_67285.classify_version("6.10.0") == "NOT_AFFECTED"
    assert cve_2026_67285.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_sppb_67285_marker_include_confirms():
    client = _FakeSppbEditorClient(include_marker=True)
    with patch.object(cve_2026_67285, "HttpClient", return_value=client):
        result = cve_2026_67285.run_aggressive_probe(
            "https://target.test", username="admin", password="proofcms-lab-password"
        )
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["benign_preview_ok"] is True
    assert result.evidence["marker_found"] is True


def test_sppb_67285_patched_addon_name_is_not_confirmed():
    client = _FakeSppbEditorClient(include_marker=False)
    with patch.object(cve_2026_67285, "HttpClient", return_value=client):
        result = cve_2026_67285.run_aggressive_probe(
            "https://target.test", username="admin", password="proofcms-lab-password"
        )
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["marker_found"] is False
    assert result.evidence["benign_preview_ok"] is True


def test_sppb_67285_bad_benign_control_is_blocked():
    client = _FakeSppbEditorClient(include_marker=False, benign_ok=False)
    with patch.object(cve_2026_67285, "HttpClient", return_value=client):
        result = cve_2026_67285.run_aggressive_probe(
            "https://target.test", username="admin", password="proofcms-lab-password"
        )
    assert result.status == "BLOCKED_EXTERNAL"


def test_sppb_67285_without_credentials_sends_nothing():
    result = cve_2026_67285.run_aggressive_probe("https://target.test")
    assert result.status == "BLOCKED_EXTERNAL"
    assert result.exploit_ran is False


# --- CVE-2026-65876 -------------------------------------------------------


def test_sppb_65876_version_boundaries():
    assert cve_2026_65876.classify_version("6.7.0") == "LIKELY_VULNERABLE"
    assert cve_2026_65876.classify_version("6.0.0") == "LIKELY_VULNERABLE"
    assert cve_2026_65876.classify_version("6.8.0") == "NOT_AFFECTED"
    assert cve_2026_65876.classify_version("6.10.0") == "NOT_AFFECTED"
    assert cve_2026_65876.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_sppb_65876_sleep_confirms():
    responses = [({"status": 200, "body": ""}, 0.20), ({"status": 200, "body": ""}, 2.20)]
    with patch.object(cve_2026_65876, "HttpClient", return_value=_DummyClient()), patch.object(
        cve_2026_65876, "_timed_post", side_effect=responses
    ):
        result = cve_2026_65876.run_aggressive_probe("https://target.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["delta_seconds"] >= cve_2026_65876.SLEEP_THRESHOLD


def test_sppb_65876_missing_endpoint_is_blocked():
    responses = [({"status": 500, "body": ""}, 0.10), ({"status": 500, "body": ""}, 0.12)]
    with patch.object(cve_2026_65876, "HttpClient", return_value=_DummyClient()), patch.object(
        cve_2026_65876, "_timed_post", side_effect=responses
    ):
        result = cve_2026_65876.run_aggressive_probe("https://target.test")
    assert result.status == "BLOCKED_EXTERNAL"


# --- CVE-2026-65766 -------------------------------------------------------


def test_sppb_65766_version_boundaries():
    assert cve_2026_65766.classify_version("6.0.0") == "LIKELY_VULNERABLE"
    assert cve_2026_65766.classify_version("6.7.0") == "LIKELY_VULNERABLE"
    assert cve_2026_65766.classify_version("6.7.1") == "NOT_AFFECTED"
    assert cve_2026_65766.classify_version("6.10.0") == "NOT_AFFECTED"
    assert cve_2026_65766.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_sppb_65766_order_sleep_confirms():
    responses = [({"status": 200, "body": ""}, 0.20), ({"status": 200, "body": ""}, 2.20)]
    with patch.object(cve_2026_65766, "HttpClient", return_value=_DummyClient()), patch.object(
        cve_2026_65766, "_timed_post", side_effect=responses
    ):
        result = cve_2026_65766.run_aggressive_probe("https://target.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"


def test_sppb_65766_patched_is_not_confirmed():
    responses = [({"status": 200, "body": ""}, 0.20), ({"status": 200, "body": ""}, 0.25)]
    with patch.object(cve_2026_65766, "HttpClient", return_value=_DummyClient()), patch.object(
        cve_2026_65766, "_timed_post", side_effect=responses
    ):
        result = cve_2026_65766.run_aggressive_probe("https://target.test")
    assert result.status == "NOT_CONFIRMED"


def test_sppb_65766_authenticated_control_is_not_affected():
    responses = [
        ({"status": 200, "body": ""}, 0.20),
        ({"status": 200, "body": '{"status":false,"message":"You don\'t have permission to access this."}'}, 0.25),
    ]
    with patch.object(cve_2026_65766, "HttpClient", return_value=_DummyClient()), patch.object(
        cve_2026_65766, "_timed_post", side_effect=responses
    ):
        result = cve_2026_65766.run_aggressive_probe("https://target.test")
    assert result.status == "NOT_AFFECTED"


def test_sppb_65766_guest_token_is_sent_in_header():
    class _TokenClient(_DummyClient):
        def get(self, url: str, timeout: int | None = None) -> dict[str, object]:
            return {"status": 200, "body": f'<input name="{TOKEN}" value="1">'}

    captured: dict[str, Any] = {}

    def fake_timed(client, url, payload, timeout, headers=None):
        captured.update(headers or {})
        return {"status": 200, "body": ""}, 0.2

    with patch.object(cve_2026_65766, "HttpClient", return_value=_TokenClient()), patch.object(
        cve_2026_65766, "_timed_post", side_effect=fake_timed
    ):
        cve_2026_65766.run_aggressive_probe("https://target.test")
    assert captured.get("X-CSRF-Token") == TOKEN


def test_sppb_65766_undispatchable_controller_is_blocked():
    responses = [({"status": 303, "body": ""}, 0.10), ({"status": 303, "body": ""}, 0.12)]
    with patch.object(cve_2026_65766, "HttpClient", return_value=_DummyClient()), patch.object(
        cve_2026_65766, "_timed_post", side_effect=responses
    ):
        result = cve_2026_65766.run_aggressive_probe("https://target.test")
    assert result.status == "BLOCKED_EXTERNAL"


def test_sppb_65766_check_skips_patched_version():
    result = cve_2026_65766.check(
        "https://target.test",
        run_exploit_check=True,
        exploit_mode="aggressive",
        plugins={"sppagebuilder": {"found": True, "version": "6.10.0"}},
    )
    assert result.status == "NOT_AFFECTED"
    assert "skipped" in result.detail
