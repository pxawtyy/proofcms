import unittest
from unittest.mock import patch

from proofcms.modules.joomla import cve_2018_15882, joomla_media_probe


class TestPharStubPayload(unittest.TestCase):
    def test_short_tag_stub_is_inert(self):
        payload = cve_2018_15882.build_inert_phar_stub("PROOFCMS_MARKER")
        self.assertIn(b"GIF89a", payload)
        self.assertIn(b"<? __HALT_COMPILER(); ?>", payload)
        self.assertNotIn(b"<?php", payload)
        self.assertNotIn(b"system(", payload)
        self.assertNotIn(b"eval(", payload)


class TestPharCheckCredentials(unittest.TestCase):
    def test_check_passes_admin_credentials(self):
        proof = {
            "accepted": True,
            "proof_url": "http://target.test/images/proofcms.gif",
            "uploaded_filename": "images/proofcms.gif",
            "surface_found": True,
        }
        with patch.object(cve_2018_15882, "probe_upload", return_value=proof) as probe:
            result = cve_2018_15882.check(
                "http://target.test",
                "3.8.11",
                run_exploit_check=True,
                exploit_mode="aggressive",
                aggressive_command="admin:secret",
            )
        self.assertEqual(result.status, "VULNERABLE_UPLOAD_ONLY")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertEqual(probe.call_args.kwargs["admin_user"], "admin")
        self.assertEqual(probe.call_args.kwargs["admin_pass"], "secret")

    def test_check_without_credentials_uses_anonymous_surface(self):
        proof = {"accepted": False, "surface_found": False, "attempts": ["no form"]}
        with patch.object(cve_2018_15882, "probe_upload", return_value=proof) as probe:
            result = cve_2018_15882.check(
                "http://target.test",
                "3.8.11",
                run_exploit_check=True,
                exploit_mode="aggressive",
            )
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertIsNone(probe.call_args.kwargs["admin_user"])


class TestMediaAdminLogin(unittest.TestCase):
    def test_admin_login_accepts_dashboard_body(self):
        class FakeSession:
            def get(self, url, timeout=None):
                return {
                    "status": 200,
                    "body": '<input type="hidden" name="' + "a" * 32 + '" value="1">',
                }

            def post(self, url, fields=None, timeout=None):
                return {"status": 500, "body": "com_cpanel"}

        self.assertTrue(joomla_media_probe.admin_login(FakeSession(), "admin", "secret"))

    def test_admin_login_rejects_login_page(self):
        class FakeSession:
            def get(self, url, timeout=None):
                return {
                    "status": 200,
                    "body": '<input type="hidden" name="' + "a" * 32 + '" value="1">',
                }

            def post(self, url, fields=None, timeout=None):
                return {"status": 200, "body": "login form"}

        self.assertFalse(joomla_media_probe.admin_login(FakeSession(), "admin", "wrong"))


if __name__ == "__main__":
    unittest.main()
