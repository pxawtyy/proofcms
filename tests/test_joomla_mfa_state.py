"""Unit tests for the Joomla stale-MFA-state bypass CVE-2026-48897."""
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

from proofcms.modules.joomla import cve_2026_48897

TOKEN = "0123456789abcdef0123456789abcdef"


def _fields(data):
    if isinstance(data, bytes):
        data = data.decode()
    return {k: v[-1] for k, v in parse_qs(data).items()}


class FakeClient:
    def __init__(self, state):
        self.state = state

    def get(self, url, **kwargs):
        if "component/users/login" in url:
            return {"status": 200, "body": f'<input type="hidden" name="{TOKEN}" value="1">', "final_url": url}
        if "view=profile" in url:
            if self.state.get("captive"):
                return {"status": 200, "body": "<html>captive</html>",
                        "final_url": "http://t/index.php/component/users/captive"}
            user = self.state.get("identity")
            body = f'<input name="jform[username]" value="{user}">' if user else "<html></html>"
            return {"status": 200, "body": body, "final_url": "http://t/profile"}
        if url.rstrip("/").endswith("/index.php"):
            return {"status": 200, "body": f'{{"csrf.token":"{TOKEN}"}}', "final_url": url}
        return {"status": 200, "body": "<html>home</html>", "final_url": url}

    def request(self, url, **kwargs):
        fields = _fields(kwargs.get("data") or b"")
        user = fields.get("username")
        if user == "plainuser":
            self.state["identity"] = "plainuser"
            self.state["captive"] = False
        elif user == "mfa_victim":
            if self.state.get("vulnerable", True):
                self.state["identity"] = "mfa_victim"
                self.state["captive"] = False
            else:
                self.state["identity"] = None
                self.state["captive"] = True
        return {"status": 303, "body": "", "final_url": url}


def _run(state):
    with patch.object(cve_2026_48897, "HttpClient", side_effect=lambda *a, **k: FakeClient(state)):
        return cve_2026_48897.run_aggressive_probe(
            "https://target.test", timeout=2,
            victim_user="mfa_victim", victim_password="pw",
            plain_user="plainuser", plain_password="pw2",
        )


class TestStaleMfaState(unittest.TestCase):
    def test_stale_flag_confirms(self):
        result = _run({"vulnerable": True})
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertEqual(result.evidence["second_login_identity"], "mfa_victim")
        self.assertFalse(result.evidence["captive_gate"])

    def test_captive_redirect_does_not_confirm(self):
        result = _run({"vulnerable": False})
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertTrue(result.evidence["captive_gate"])

    def test_missing_credentials_blocks(self):
        result = cve_2026_48897.run_aggressive_probe("https://target.test", timeout=2)
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")
        self.assertFalse(result.exploit_ran)

    def test_version_gates(self):
        self.assertEqual(cve_2026_48897.classify_version("5.4.5"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_48897.classify_version("5.4.6"), "PATCHED")
        self.assertEqual(cve_2026_48897.classify_version("6.1.0"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_48897.classify_version("6.1.1"), "PATCHED")
        self.assertEqual(cve_2026_48897.classify_version("3.10.12"), "NOT_AFFECTED")
        self.assertEqual(cve_2026_48897.classify_version(None), "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
