import unittest
from unittest.mock import patch

from proofcms.modules.wordpress import cve_2023_32243

HOME_HTML = """
<script id='eael-general-js-extra'>
var eael = {"ajaxurl":"https://target.test/wp-admin/admin-ajax.php","nonce":"abc123def0","eael_resetpassword_nonce":"deadbeef01"};
</script>
"""


class FakeSession:
    def __init__(self, *, accepted=True, login_ok=True):
        self.accepted = accepted
        self.login_ok = login_ok
        self.posts = []

    def get(self, url, headers=None, timeout=None):
        if url in ("/", "https://target.test/"):
            return {"status": 200, "body": HOME_HTML}
        if url == "/wp-login.php":
            return {"status": 200, "body": "login"}
        return {"status": 404, "body": ""}

    def post(self, url, data=None, fields=None, files=None, headers=None, timeout=None):
        self.posts.append((url, fields or {}))
        if "eael-login-register-form" in url:
            if self.accepted:
                return {
                    "status": 200,
                    "body": '{"success":true,"data":{"message":"Your password has been reset."}}',
                }
            return {"status": 200, "body": '{"success":false,"data":{"message":"Invalid user name found!"}}'}
        if url == "/wp-login.php":
            if self.login_ok:
                return {
                    "status": 200,
                    "final_url": "https://target.test/wp-admin/",
                    "body": "Dashboard",
                }
            return {"status": 200, "final_url": "https://target.test/wp-login.php", "body": "Login"}
        return {"status": 404, "body": ""}


class TestEssentialAddonsVersionPolicy(unittest.TestCase):
    def test_version_boundary(self):
        self.assertEqual(cve_2023_32243.classify_version("5.4.0"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2023_32243.classify_version("5.7.1"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2023_32243.classify_version("5.7.2"), "PATCHED")
        self.assertEqual(cve_2023_32243.classify_version("5.3.9"), "NOT_AFFECTED")
        self.assertEqual(cve_2023_32243.classify_version(None), "DETECTED_VERSION_UNKNOWN")


class TestEssentialAddonsNonceParsing(unittest.TestCase):
    def test_extracts_generic_nonce(self):
        self.assertEqual(cve_2023_32243._eael_nonce(HOME_HTML), "abc123def0")


class TestEssentialAddonsResetProbe(unittest.TestCase):
    def test_reset_and_login_is_confirmed(self):
        fake = FakeSession()
        with patch.object(cve_2023_32243, "HttpSession", return_value=fake):
            result = cve_2023_32243.run_aggressive_probe("https://target.test", username="admin")
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        assert result.evidence is not None
        self.assertTrue(result.evidence["login_verified"])
        self.assertEqual(result.evidence["target_user"], "admin")
        reset_fields = next(fields for url, fields in fake.posts if "eael-login-register-form" in url)
        self.assertEqual(reset_fields["eael-resetpassword-nonce"], "abc123def0")
        self.assertEqual(reset_fields["rp_login"], "admin")

    def test_rejected_reset_is_not_confirmed(self):
        fake = FakeSession(accepted=False)
        with patch.object(cve_2023_32243, "HttpSession", return_value=fake):
            result = cve_2023_32243.run_aggressive_probe("https://target.test")
        self.assertEqual(result.status, "NOT_CONFIRMED")

    def test_success_without_login_is_upload_only(self):
        fake = FakeSession(login_ok=False)
        with patch.object(cve_2023_32243, "HttpSession", return_value=fake):
            result = cve_2023_32243.run_aggressive_probe("https://target.test")
        self.assertEqual(result.status, "VULNERABLE_UPLOAD_ONLY")


class TestEssentialAddonsCheckGate(unittest.TestCase):
    def test_patched_version_skips_probe(self):
        plugins = {"essential-addons-for-elementor-lite": {"found": True, "version": "5.7.2"}}
        with patch.object(cve_2023_32243, "run_aggressive_probe") as probe:
            result = cve_2023_32243.check(
                "https://target.test",
                run_exploit_check=True,
                exploit_mode="aggressive",
                plugins=plugins,
            )
        self.assertEqual(result.status, "PATCHED")
        self.assertFalse(result.exploit_ran)
        probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
