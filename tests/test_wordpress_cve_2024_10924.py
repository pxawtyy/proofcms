import types
import unittest
from unittest.mock import patch

from proofcms.modules.wordpress import cve_2024_10924


class FakeSession:
    def __init__(self, *, status=200, cookie=True, admin=True):
        self.status = status
        self.cookie = cookie
        self.admin = admin
        self.jar = []

    def post(self, url, data=None, headers=None, timeout=None):
        if self.status == 200 and self.cookie:
            self.jar.append(types.SimpleNamespace(name="wordpress_logged_in_test"))
            return {"status": 200, "body": '{"redirect_to":"/wp-admin/"}'}
        if self.status == 404:
            return {"status": 404, "body": '{"code":"rest_no_route"}'}
        return {"status": self.status, "body": '{"error":"Invalid login nonce"}'}

    def get(self, url, headers=None, timeout=None):
        if self.admin:
            return {
                "status": 200,
                "final_url": "https://target.test/wp-admin/admin.php?page=really-simple-security",
                "body": "Dashboard",
            }
        return {"status": 302, "final_url": "https://target.test/wp-login.php", "body": "Login"}


class TestReallySimpleSecurityVersionPolicy(unittest.TestCase):
    def test_version_boundary(self):
        self.assertEqual(cve_2024_10924.classify_version("9.0.0"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2024_10924.classify_version("9.1.1.1"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2024_10924.classify_version("9.1.2"), "PATCHED")
        self.assertEqual(cve_2024_10924.classify_version("8.9.9"), "NOT_AFFECTED")
        self.assertEqual(cve_2024_10924.classify_version(None), "DETECTED_VERSION_UNKNOWN")


class TestReallySimpleSecurityProbe(unittest.TestCase):
    def test_invalid_nonce_session_is_confirmed(self):
        fake = FakeSession()
        with patch.object(cve_2024_10924, "HttpSession", return_value=fake):
            result = cve_2024_10924.run_safe_probe("https://target.test")
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertTrue(result.exploit_ran)
        assert result.evidence is not None
        self.assertTrue(result.evidence["login_cookie_set"])
        self.assertTrue(result.evidence["admin_dashboard"])

    def test_missing_route_is_not_confirmed(self):
        fake = FakeSession(status=404, cookie=False)
        with patch.object(cve_2024_10924, "HttpSession", return_value=fake):
            result = cve_2024_10924.run_safe_probe("https://target.test")
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertIn("2FA", result.detail)

    def test_no_cookie_is_not_confirmed(self):
        fake = FakeSession(cookie=False)
        with patch.object(cve_2024_10924, "HttpSession", return_value=fake):
            result = cve_2024_10924.run_safe_probe("https://target.test")
        self.assertEqual(result.status, "NOT_CONFIRMED")


class TestReallySimpleSecurityCheckGate(unittest.TestCase):
    def test_patched_version_skips_probe(self):
        plugins = {"really-simple-ssl": {"found": True, "version": "9.1.2"}}
        with patch.object(cve_2024_10924, "run_safe_probe") as probe:
            result = cve_2024_10924.check(
                "https://target.test",
                run_exploit_check=True,
                exploit_mode="safe",
                plugins=plugins,
            )
        self.assertEqual(result.status, "PATCHED")
        self.assertFalse(result.exploit_ran)
        probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
