"""Unit tests for the Joomla MFA bypass CVE-2026-92227 aggressive probe."""
import unittest
from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_92227


def _home(authenticated=True, mfa=False, user="mfa_victim"):
    if mfa:
        return "<html><body>Multi-factor Authentication verification code</body></html>"
    if authenticated:
        return f"<html><body><a>Log out</a><span>{user}</span></body></html>"
    return "<html><body>Username Password Log in</body></html>"


class FakeClient:
    def __init__(self, home_body):
        self.home_body = home_body
        self.jar = []

    def get(self, url, **kwargs):
        if "users/login" in url:
            return {"status": 200,
                    "body": '<form><input name="0123456789abcdef0123456789abcdef" value="1"></form>',
                    "headers": {}}
        return {"status": 200, "body": self.home_body, "headers": {}}

    def request(self, url, **kwargs):
        self.jar.append("remember-me-set")
        return {"status": 303, "body": "", "headers": {}}


def _run(home_body, **kwargs):
    with (
        patch.object(cve_2026_92227, "HttpClient", return_value=FakeClient(home_body)),
        patch.object(cve_2026_92227, "_remember_cookie_from_jar",
                     return_value=("joomla_remember_me_x", "tok.ser")),
    ):
        return cve_2026_92227.run_aggressive_probe("https://target.test", timeout=2, **kwargs)


class TestMfaBypassProbe(unittest.TestCase):
    def test_cookie_session_fully_authenticated_confirms(self):
        result = _run(_home(True, False), victim_user="mfa_victim", victim_password="pw")
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertTrue(result.exploit_ran)
        self.assertTrue(result.evidence["session_authenticated"])

    def test_cookie_session_hitting_captive_does_not_confirm(self):
        result = _run(_home(True, True), victim_user="mfa_victim", victim_password="pw")
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertTrue(result.evidence["mfa_gate_seen"])

    def test_missing_credentials_blocks(self):
        result = cve_2026_92227.run_aggressive_probe("https://target.test", timeout=2)
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")
        self.assertFalse(result.exploit_ran)

    def test_version_gates(self):
        self.assertEqual(cve_2026_92227.classify_version("5.4.8"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_92227.classify_version("6.1.3"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_92227.classify_version("5.4.9"), "PATCHED")
        self.assertEqual(cve_2026_92227.classify_version("6.1.4"), "PATCHED")
        self.assertEqual(cve_2026_92227.classify_version("3.10.12"), "NOT_AFFECTED")
        self.assertEqual(cve_2026_92227.classify_version(None), "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
