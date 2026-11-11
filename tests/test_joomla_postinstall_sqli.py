"""Unit tests for the Joomla Hathor postinstall SQLi CVE-2018-6376 probe."""
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

from proofcms.modules.joomla import cve_2018_6376

TOKEN = "0123456789abcdef0123456789abcdef"
PROFILE_HTML = f"""
<html><body>
<form action="/administrator/index.php?option=com_admin&amp;view=profile&amp;layout=edit&amp;id=2" method="post">
  <input type="hidden" name="{TOKEN}" value="1">
  <input type="text" name="jform[name]" value="Lab Manager">
  <input type="text" name="jform[username]" value="mgr">
  <input type="text" name="jform[email]" value="mgr@example.test">
  <input type="hidden" name="jform[id]" value="2">
  <input type="password" name="jform[password]" value="">
  <select name="jform[params][admin_style]"><option value="">Use default</option></select>
  <input type="hidden" name="task" value="">
</form>
</body></html>
"""
LOGIN_HTML = f'<html><body><form method="post"><input type="hidden" name="{TOKEN}" value="1"></form></body></html>'


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class FakeClient:
    def __init__(self, clock, sleep_on_payload=True, login_page=True, profile_page=True):
        self.clock = clock
        self.sleep_on_payload = sleep_on_payload
        self.login_page = login_page
        self.profile_page = profile_page
        self.logged_in = False
        self.stored = ""
        self.posts = []

    def get(self, url, **kwargs):
        if url.endswith("/administrator/index.php"):
            if not self.logged_in:
                return {"status": 200, "body": LOGIN_HTML if self.login_page else "<html></html>", "headers": {}}
            if self.stored and "SLEEP" in self.stored and self.sleep_on_payload:
                self.clock.advance(6.0)
            return {"status": 200, "body": "<html><body>Control Panel</body></html>", "headers": {}}
        if "option=com_admin" in url:
            body = PROFILE_HTML if self.profile_page else "<html><body>no form</body></html>"
            return {"status": 200, "body": body, "headers": {}}
        return {"status": 200, "body": "<html>home</html>", "headers": {}}

    def request(self, url, **kwargs):
        data = kwargs.get("data") or b""
        if isinstance(data, bytes):
            data = data.decode()
        fields = {k: v[-1] for k, v in parse_qs(data).items()}
        self.posts.append(fields)
        if fields.get("task") == "login":
            self.logged_in = True
        if fields.get("task") == "profile.save":
            self.stored = fields.get("jform[params][admin_style][0]", "")
        return {"status": 303, "body": "", "headers": {}}


def _run(client, **kwargs):
    with patch.object(cve_2018_6376, "HttpClient", return_value=client):
        return cve_2018_6376.run_aggressive_probe(
            "https://target.test", timeout=2, clock=client.clock, **kwargs
        )


class TestPostinstallSqliProbe(unittest.TestCase):
    def test_time_delay_confirms(self):
        clock = FakeClock()
        client = FakeClient(clock, sleep_on_payload=True)
        result = _run(client, admin_user="mgr", admin_password="pw")
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertTrue(result.evidence["payload_stored"])
        self.assertGreaterEqual(result.evidence["delay_seconds"], 2.5)
        # the probe restores a benign value after the proof
        self.assertEqual(client.stored, cve_2018_6376.BENIGN_STYLE)

    def test_no_delay_does_not_confirm(self):
        clock = FakeClock()
        client = FakeClient(clock, sleep_on_payload=False)
        result = _run(client, admin_user="mgr", admin_password="pw")
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertTrue(result.evidence["payload_stored"])

    def test_missing_credentials_blocks(self):
        result = cve_2018_6376.run_aggressive_probe("https://target.test", timeout=2)
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")
        self.assertFalse(result.exploit_ran)

    def test_login_form_unavailable(self):
        clock = FakeClock()
        client = FakeClient(clock, login_page=False)
        result = _run(client, admin_user="mgr", admin_password="pw")
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertIn("login form", result.detail)

    def test_profile_form_unavailable(self):
        clock = FakeClock()
        client = FakeClient(clock, profile_page=False)
        result = _run(client, admin_user="mgr", admin_password="pw")
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertIn("profile", result.detail)

    def test_version_gates(self):
        self.assertEqual(cve_2018_6376.classify_version("3.7.0"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2018_6376.classify_version("3.8.3"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2018_6376.classify_version("3.8.4"), "PATCHED")
        self.assertEqual(cve_2018_6376.classify_version("3.8.11"), "PATCHED")
        self.assertEqual(cve_2018_6376.classify_version("3.6.5"), "NOT_AFFECTED")
        self.assertEqual(cve_2018_6376.classify_version(None), "INCONCLUSIVE")

    def test_check_runs_only_in_aggressive_mode_on_affected_versions(self):
        clock = FakeClock()
        client = FakeClient(clock)
        with patch.object(cve_2018_6376, "HttpClient", return_value=client):
            passive = cve_2018_6376.check(
                "https://target.test", joomla_version="3.8.3", run_exploit_check=True,
                exploit_mode="safe",
            )
            self.assertEqual(passive.status, "LIKELY_VULNERABLE")
            gated = cve_2018_6376.check(
                "https://target.test", joomla_version="3.8.11", run_exploit_check=True,
                exploit_mode="aggressive", aggressive_args={"admin_user": "mgr", "admin_password": "pw"},
            )
            self.assertEqual(gated.status, "PATCHED")


if __name__ == "__main__":
    unittest.main()
