"""Unit tests for the Joomla MFA method-add bypass CVE-2025-25227."""
import unittest
from unittest.mock import patch

from proofcms.modules.joomla import cve_2025_25227

TOKEN = "0123456789abcdef0123456789abcdef"


class FakeClient:
    def __init__(self, state):
        self.state = state

    def get(self, url, **kwargs):
        if "component/users/login" in url:
            return {"status": 200, "body": f'<input type="hidden" name="{TOKEN}" value="1">', "final_url": url}
        if "view=profile" in url:
            return {"status": 200, "body": "<html>captive</html>",
                    "final_url": "http://t/index.php/component/users/captive"}
        if "task=method.add" in url:
            if self.state.get("vulnerable", True):
                return {"status": 500, "body": "error", "final_url": "http://t/index.php?option=com_users&task=method.add"}
            return {"status": 200, "body": "captive", "final_url": "http://t/index.php/component/users/captive"}
        return {"status": 200, "body": "<html></html>", "final_url": url}

    def request(self, url, **kwargs):
        return {"status": 303, "body": "", "final_url": url}


def _run(state):
    with patch.object(cve_2025_25227, "HttpClient", side_effect=lambda *a, **k: FakeClient(state)):
        return cve_2025_25227.run_aggressive_probe(
            "https://target.test", timeout=2,
            victim_user="mfa_victim", victim_password="pw",
        )


class TestMfaMethodAddBypass(unittest.TestCase):
    def test_method_add_without_captive_confirms(self):
        result = _run({"vulnerable": True})
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertTrue(result.evidence["profile_captive"])
        self.assertFalse(result.evidence["methods_captive"])

    def test_captive_redirect_does_not_confirm(self):
        result = _run({"vulnerable": False})
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertTrue(result.evidence["methods_captive"])

    def test_missing_credentials_blocks(self):
        result = cve_2025_25227.run_aggressive_probe("https://target.test", timeout=2)
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")

    def test_version_gates(self):
        self.assertEqual(cve_2025_25227.classify_version("5.2.5"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2025_25227.classify_version("5.2.6"), "PATCHED")
        self.assertEqual(cve_2025_25227.classify_version("4.4.12"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2025_25227.classify_version("4.4.13"), "PATCHED")
        self.assertEqual(cve_2025_25227.classify_version("3.10.12"), "NOT_AFFECTED")
        self.assertEqual(cve_2025_25227.classify_version(None), "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
