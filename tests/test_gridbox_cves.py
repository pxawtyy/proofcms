"""Regression tests for the Gridbox 2.20.2 CVE set (CVE-2026-65884..65890, 65947)."""
import re
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from proofcms.modules.joomla import (
    cve_2026_65884,
    cve_2026_65885,
    cve_2026_65886,
    cve_2026_65887,
    cve_2026_65888,
    cve_2026_65889,
    cve_2026_65890,
    cve_2026_65947,
    cve_2026_102784,
)

TOKEN = "0123456789abcdef0123456789abcdef"


def _fields(data):
    if isinstance(data, bytes):
        data = data.decode()
    return {k: v[-1] for k, v in parse_qs(data).items()}


class FakeClient:
    """Stateful fake for the Gridbox endpoints used by the probe modules."""

    def __init__(self, state):
        self.state = state

    def get(self, url, **kwargs):
        s = self.state
        if url.rstrip("/").endswith("/administrator/index.php"):
            if s.get("admin_logged_in"):
                return {"status": 200, "body": "<html>com_cpanel logout</html>", "headers": {}}
            return {"status": 200, "body": f'<form><input type="hidden" name="{TOKEN}" value="1"><input name="passwd"></form>', "headers": {}}
        if "pages.unpublish" in url:
            if s.get("csrf", True):
                s["published"] = False
                return {"status": 200, "body": "Item(s) was successfully unpublished", "headers": {}}
            return {"status": 403, "body": "Invalid token", "headers": {}}
        if "pages.publish" in url:
            if s.get("csrf", True):
                s["published"] = True
                return {"status": 200, "body": "Item(s) was successfully published", "headers": {}}
            return {"status": 403, "body": "Invalid token", "headers": {}}
        if "view=page&id=" in url:
            return {"status": 200 if s.get("published", True) else 404, "body": "<html>page</html>", "headers": {}}
        if "component/users/login" in url:
            return {"status": 200, "body": f'<input type="hidden" name="{TOKEN}" value="1">', "headers": {}}
        if "com_users&view=profile" in url:
            user = s.get("identity")
            body = f'<input name="jform[username]" value="{user}">' if user else "<html></html>"
            return {"status": 200, "body": body, "headers": {}}
        if "uploader.showImage" in url:
            marker = s.get("read_marker", "")
            return {"status": 200 if s.get("read") else 404, "body": marker if s.get("read") else "", "headers": {}}
        if "editor.generateNewApp" in url:
            if s.get("delete", True):
                s["canary"] = False
                return {"status": 200, "body": "created", "headers": {}}
            return {"status": 404, "body": "", "headers": {}}
        if "/tmp/" in url and "marker.txt" in url:
            return {"status": 200 if s.get("canary", True) else 404,
                    "body": "GB_DELETE_CANARY" if s.get("canary", True) else "", "headers": {}}
        if "/images/" in url and s.get("upload_marker"):
            return {"status": 200, "body": s["upload_marker"], "headers": {}}
        return {"status": 200, "body": "<html>home</html>", "headers": {}}

    def request(self, url, **kwargs):
        s = self.state
        query = {k: v[-1] for k, v in parse_qs(urlparse(url).query).items()}
        fields = {**query, **_fields(kwargs.get("data") or b"")}
        task = fields.get("task", "")
        if task == "login":
            s["admin_logged_in"] = bool(s.get("admin_ok", True))
        elif task == "user.login":
            s["identity"] = s.get("login_identity") or s.get("victim_user")
        elif task == "store.register":
            return {"status": 200, "body": '{"status":true}' if s.get("register") else '{"status":false}', "headers": {}}
        elif task == "account.socialLogin":
            if s.get("social"):
                s["identity"] = s.get("social_identity")
                return {"status": 200, "body": '{"status":true}', "headers": {}}
            return {"status": 404, "body": "", "headers": {}}
        elif task == "account.remindPassword":
            return {"status": 200, "body": f'{{"status":true,"message":"{s.get("reset_token", "")}"}}', "headers": {}}
        elif task == "account.requestPassword":
            return {"status": 200, "body": f'{{"status":true,"id":{s.get("uid", 0)}}}', "headers": {}}
        elif task == "account.resetPassword":
            if s.get("reset"):
                s["identity"] = s.get("victim_user")
            return {"status": 200, "body": '{"status":true}', "headers": {}}
        elif "comments.getCommentsPatterns" in url:
            injected = "1=2" in fields.get("id", "")
            if not s.get("sqli_differential", True):
                injected = False
            body = '{"commentsCount":"Be the first to comment","comments":""}' if injected else '{"commentsCount":"1 Comments","comments":"<div>c</div>"}'
            return {"status": 200, "body": body, "headers": {}}
        elif "uploader.executeAction" in url and "uploadFile" in url:
            if s.get("upload"):
                s["uploaded"] = True
                match = re.search(rb"GB_UPLOAD_65885_[a-z0-9]+", kwargs.get("data") or b"")
                if match:
                    s["upload_marker"] = match.group(0).decode()
            return {"status": 200, "body": '{"name":"gb.shtml","url":"images/gb.shtml"}', "headers": {}}
        return {"status": 200, "body": "", "headers": {}}


def _run(module, state, **kwargs):
    with patch.object(module, "HttpClient", side_effect=lambda *a, **k: FakeClient(state)):
        return module.run_aggressive_probe("https://target.test", timeout=2, **kwargs)


class TestGridboxCves(unittest.TestCase):
    def test_65884_registration_confirms_and_negative(self):
        self.assertEqual(_run(cve_2026_65884, {"register": True, "admin": True}).status, "VULNERABLE")
        self.assertEqual(_run(cve_2026_65884, {"register": False, "admin": False}).status, "NOT_CONFIRMED")

    def test_65888_social_confirms_and_negative(self):
        ok = _run(cve_2026_65888, {"social": True, "social_identity": "admin"}, victim_email="lab@example.test", victim_user="admin")
        self.assertEqual(ok.status, "VULNERABLE")
        bad = _run(cve_2026_65888, {"social": False}, victim_email="lab@example.test", victim_user="admin")
        self.assertEqual(bad.status, "NOT_CONFIRMED")

    def test_65887_reset_confirms_and_negative(self):
        ok = _run(cve_2026_65887, {"reset_token": "a" * 32, "uid": 7, "reset": True, "victim_user": "labvictim"},
                  victim_user="labvictim", victim_email="v@example.test")
        self.assertEqual(ok.status, "VULNERABLE")
        bad = _run(cve_2026_65887, {"reset_token": "", "uid": 0, "reset": False},
                   victim_user="labvictim", victim_email="v@example.test")
        self.assertEqual(bad.status, "NOT_CONFIRMED")

    def test_65886_read_confirms_and_negative(self):
        self.assertEqual(_run(cve_2026_65886, {"read": True, "read_marker": "class JConfig"}).status, "VULNERABLE")
        self.assertEqual(_run(cve_2026_65886, {"read": False}).status, "NOT_CONFIRMED")

    def test_65889_delete_confirms_blocks_and_negative(self):
        self.assertEqual(_run(cve_2026_65889, {"canary": True, "delete": True}).status, "VULNERABLE")
        self.assertEqual(_run(cve_2026_65889, {"canary": False}).status, "BLOCKED_EXTERNAL")
        self.assertEqual(_run(cve_2026_65889, {"canary": True, "delete": False}).status, "NOT_CONFIRMED")

    def test_65885_upload_confirms_and_negative(self):
        state = {"upload": True}
        result = _run(cve_2026_65885, state, admin_user="admin", admin_password="pw")
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertEqual(_run(cve_2026_65885, {"upload": False}, admin_user="admin", admin_password="pw").status, "NOT_CONFIRMED")

    def test_65890_sqli_confirms_and_negative(self):
        self.assertEqual(_run(cve_2026_65890, {}, page_id="1").status, "VULNERABLE")
        self.assertEqual(_run(cve_2026_65890, {"sqli_differential": False}, page_id="1").status, "NOT_CONFIRMED")

    def test_65947_csrf_confirms_and_negative(self):
        ok = _run(cve_2026_65947, {"csrf": True}, admin_user="admin", admin_password="pw", page_id="1")
        self.assertEqual(ok.status, "VULNERABLE")
        bad = _run(cve_2026_65947, {"csrf": False}, admin_user="admin", admin_password="pw", page_id="1")
        self.assertEqual(bad.status, "NOT_CONFIRMED")

    def test_version_gates(self):
        for module, fixed in (
            (cve_2026_65884, "2.20.2"), (cve_2026_65885, "2.20.2"), (cve_2026_65886, "2.20.2"),
            (cve_2026_65887, "2.20.2"), (cve_2026_65888, "2.20.2"), (cve_2026_65889, "2.20.2"),
            (cve_2026_65890, "2.20.2"), (cve_2026_65947, "2.20.2"),
        ):
            self.assertEqual(module.check("https://t.test", plugins={"gridbox": {"found": True, "version": "2.20.0.2"}}).status, "LIKELY_VULNERABLE")
            self.assertEqual(module.check("https://t.test", plugins={"gridbox": {"found": True, "version": "2.20.5.0"}}).status, "PATCHED")
        self.assertEqual(cve_2026_102784.check("https://t.test", plugins={"gridbox": {"found": True, "version": "2.20.3.1"}}).status, "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_102784.check("https://t.test", plugins={"gridbox": {"found": True, "version": "2.20.5.0"}}).status, "PATCHED")


if __name__ == "__main__":
    unittest.main()
