import unittest
from unittest.mock import patch

from proofcms.detectors import wordpress
from proofcms.modules.wordpress import cve_2024_10402, cve_2026_15748, cve_2026_92229


class TestForminatorVersionPolicies(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual(cve_2026_92229.classify_version("1.57.2"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_92229.classify_version("1.57.3"), "PATCHED")
        self.assertEqual(cve_2026_15748.classify_version("1.18.0"), "NOT_AFFECTED")
        self.assertEqual(cve_2026_15748.classify_version("1.56.1"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_15748.classify_version("1.56.2"), "PATCHED")
        self.assertEqual(cve_2024_10402.classify_version("1.35.1"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2024_10402.classify_version("1.36.0"), "PATCHED")

    def test_missing_plugin(self):
        for module in (cve_2026_92229, cve_2026_15748, cve_2024_10402):
            with self.subTest(cve=module.CVE_ID):
                self.assertEqual(module.check("https://target.test", plugins={}).status, "NOT_DETECTED")

    def test_authorization_probe_is_explicitly_blocked(self):
        result = cve_2024_10402.check(
            "https://target.test", run_exploit_check=True, plugins={"forminator": {"found": True, "version": "1.35.1"}}
        )
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")


class _WizardClient:
    """Contributor-session stand-in for the Forminator wizard request."""

    def __init__(self, wizard_status: int, wizard_location: str = "", login_status: int = 302):
        self.wizard_status = wizard_status
        self.wizard_location = wizard_location
        self.login_status = login_status
        self.calls: list[tuple[str, str]] = []

    def get(self, url: str, timeout: int | None = None) -> dict[str, object]:
        self.calls.append(("GET", url))
        return {"status": 200, "body": "<html></html>"}

    def request(self, url: str, method: str = "GET", headers=None, data=None, timeout=None, follow_redirects=True):
        self.calls.append((method, url))
        if url.endswith("/wp-login.php"):
            return {"status": self.login_status, "headers": {"Location": "https://target.test/wp-admin/"}, "body": ""}
        return {"status": self.wizard_status, "headers": {"Location": self.wizard_location}, "body": ""}


class TestForminatorContributorAuthorizationProbe(unittest.TestCase):
    def test_contributor_created_form_is_confirmed(self):
        client = _WizardClient(
            403,
            "https://target.test/wp-admin/admin.php?page=forminator-cform-wizard&id=42",
        )
        with patch.object(cve_2024_10402, "HttpClient", return_value=client):
            result = cve_2024_10402.run_aggressive_probe(
                "https://target.test", username="contributor", password="proofcms-contributor"
            )
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertEqual(result.evidence["created_form_id"], 42)
        self.assertFalse(result.cleanup_attempted)

    def test_patched_wizard_redirect_is_not_confirmed(self):
        client = _WizardClient(403)
        with patch.object(cve_2024_10402, "HttpClient", return_value=client):
            result = cve_2024_10402.run_aggressive_probe(
                "https://target.test", username="contributor", password="proofcms-contributor"
            )
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertIsNone(result.evidence["created_form_id"])
        self.assertIn("create_nonce gate", result.detail)

    def test_missing_credentials_blocks_before_login(self):
        result = cve_2024_10402.run_aggressive_probe("https://target.test")
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")
        self.assertFalse(result.exploit_ran)

    def test_failed_login_is_not_confirmed(self):
        client = _WizardClient(403, login_status=200)
        with patch.object(cve_2024_10402, "HttpClient", return_value=client):
            result = cve_2024_10402.run_aggressive_probe(
                "https://target.test", username="contributor", password="wrong"
            )
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertIn("login did not establish", result.detail)

    def test_cleanup_uses_bulk_delete_action(self):
        class _AdminClient:
            def __init__(self):
                self.deleted = False
                self.posted: dict[str, str] = {}

            def get(self, url: str, timeout: int | None = None) -> dict[str, object]:
                body = '<input name="forminatorNonce" value="nonce123">'
                if not self.deleted:
                    body += "proofcms-10402-marker"
                return {"status": 200, "body": body}

            def request(self, url: str, method: str = "GET", headers=None, data=None, timeout=None, follow_redirects=True):
                if method == "POST":
                    self.posted = {k: v for k, v in (item.split("=", 1) for item in (data or b"").decode().split("&"))}
                    self.deleted = True
                return {"status": 200, "body": ""}

        admin = _AdminClient()
        self.assertTrue(cve_2024_10402._delete_form(admin, "https://target.test", 42, "proofcms-10402-marker", 12))
        self.assertEqual(admin.posted["forminator_action"], "delete-forms")
        self.assertEqual(admin.posted["ids"], "42")
        self.assertEqual(admin.posted["forminatorNonce"], "nonce123")


class TestForminatorDiscovery(unittest.TestCase):
    def test_forminator_readme_marker(self):
        def fake_fetch(url, timeout, proxy=None):
            if url.endswith("/wp-content/plugins/forminator/readme.txt"):
                return {"status": 200, "body": "=== Forminator ===\nStable tag: 1.56.1", "body_hash": "forminator"}
            return {"status": 404, "body": "", "body_hash": "missing"}

        with patch.object(wordpress, "_fetch", side_effect=fake_fetch), patch.object(wordpress, "is_baseline_match", return_value=False):
            inventory = wordpress.detect_wordpress_plugins("https://target.test", timeout=2)
        self.assertEqual(inventory["plugins"]["forminator"]["version"], "1.56.1")

    def test_plugin_main_file_overrides_stale_asset_query(self):
        def fake_fetch(url, timeout, proxy=None):
            if url.endswith("/wp-content/plugins/elementor-pro/elementor-pro.php"):
                return {"status": 200, "body": "<?php\n/* Plugin Name: Elementor Pro\n * Version: 4.2.3\n */", "body_hash": "main"}
            if url.endswith("/wp-content/plugins/elementor-pro/readme.txt"):
                return {"status": 404, "body": "", "body_hash": "missing"}
            if url.endswith("/"):
                return {"status": 200, "body": '<script src="/wp-content/plugins/elementor-pro/assets/app.js?ver=3.28.1"></script>', "body_hash": "home"}
            return {"status": 404, "body": "", "body_hash": "missing"}

        with patch.object(wordpress, "_fetch", side_effect=fake_fetch), patch.object(wordpress, "is_baseline_match", return_value=False):
            inventory = wordpress.detect_wordpress_plugins("https://target.test", timeout=2)
        self.assertEqual(inventory["plugins"]["elementor-pro"]["version"], "4.2.3")
        self.assertIn("elementor-pro.php", inventory["plugins"]["elementor-pro"]["source"])

    def test_quiz_absence_blocks_external_shortcode_proof(self):
        with patch.object(cve_2026_92229, "discover_forms", return_value=[]):
            result = cve_2026_92229.run_safe_probe("https://target.test")
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")

    def test_shortcode_evaluation_confirms_rce_vector(self):
        page = (
            '<input type="hidden" name="form_id" value="7">'
            '<input type="hidden" name="forminator_nonce" value="abc123">'
            '<input type="radio" name="answers[q1]" value="0">'
        )
        with (
            patch.object(cve_2026_92229, "discover_forms", return_value=[{"has_quiz": True, "form_ids": ["7"], "page_url": "https://target.test/quiz/"}]),
            patch.object(cve_2026_92229, "request") as req,
            patch.object(cve_2026_92229, "rand_str", return_value="testmark"),
        ):
            req.side_effect = [
                {"status": 200, "body": page},
                {"status": 200, "body": '{"success":true,"data":{"finalText":"<div>Module ID attribute is required!<div data-url=\\"http://proofcmstestmarkModule ID attribute is required!\\">"}}'},
            ]
            result = cve_2026_92229.run_safe_probe("https://target.test")
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertTrue(result.evidence["shortcode_evaluated"])

    def test_stripped_shortcode_is_not_confirmed(self):
        page = (
            '<input type="hidden" name="form_id" value="7">'
            '<input type="hidden" name="forminator_nonce" value="abc123">'
            '<input type="radio" name="answers[q1]" value="0">'
        )
        with (
            patch.object(cve_2026_92229, "discover_forms", return_value=[{"has_quiz": True, "form_ids": ["7"], "page_url": "https://target.test/quiz/"}]),
            patch.object(cve_2026_92229, "request") as req,
            patch.object(cve_2026_92229, "rand_str", return_value="testmark"),
        ):
            req.side_effect = [
                {"status": 200, "body": page},
                {"status": 200, "body": '{"success":true,"data":{"finalText":"<div data-url=\\"http://proofcmstestmark\\">"}}'},
            ]
            result = cve_2026_92229.run_safe_probe("https://target.test")
        self.assertEqual(result.status, "NOT_CONFIRMED")


class TestPluginVersionSourcePriority(unittest.TestCase):
    def test_main_file_version_beats_stale_readme(self):
        def fake_fetch(url, timeout, proxy=None):
            if url.endswith("/wp-content/plugins/forminator/forminator.php"):
                return {"status": 200, "body": "<?php\n/*\n * Plugin Name: Forminator\n * Version: 1.57.2\n */", "body_hash": "main"}
            if url.endswith("/wp-content/plugins/forminator/readme.txt"):
                return {"status": 200, "body": "=== Forminator ===\nStable tag: 1.57.1", "body_hash": "readme"}
            return {"status": 404, "body": "", "body_hash": "missing"}

        with patch.object(wordpress, "_fetch", side_effect=fake_fetch), patch.object(wordpress, "is_baseline_match", return_value=False):
            inventory = wordpress.detect_wordpress_plugins("https://target.test", timeout=2)
        self.assertEqual(inventory["plugins"]["forminator"]["version"], "1.57.2")
        self.assertIn("forminator.php", inventory["plugins"]["forminator"]["source"])

    def test_readme_is_fallback_when_main_file_missing(self):
        def fake_fetch(url, timeout, proxy=None):
            if url.endswith("/wp-content/plugins/forminator/forminator.php"):
                return {"status": 404, "body": "not found", "body_hash": "missing"}
            if url.endswith("/wp-content/plugins/forminator/readme.txt"):
                return {"status": 200, "body": "=== Forminator ===\nStable tag: 1.56.1", "body_hash": "readme"}
            return {"status": 404, "body": "", "body_hash": "missing"}

        with patch.object(wordpress, "_fetch", side_effect=fake_fetch), patch.object(wordpress, "is_baseline_match", return_value=False):
            inventory = wordpress.detect_wordpress_plugins("https://target.test", timeout=2)
        self.assertEqual(inventory["plugins"]["forminator"]["version"], "1.56.1")
        self.assertIn("readme.txt", inventory["plugins"]["forminator"]["source"])

    def test_nonstandard_main_file_is_detected(self):
        def fake_fetch(url, timeout, proxy=None):
            if url.endswith("/wp-content/plugins/contact-form-7/wp-contact-form-7.php"):
                return {"status": 200, "body": "<?php\n/*\n * Plugin Name: Contact Form 7\n * Version: 5.3.1\n */", "body_hash": "main"}
            if url.endswith("/wp-content/plugins/contact-form-7/readme.txt"):
                return {"status": 200, "body": "=== Contact Form 7 ===\nStable tag: 5.3", "body_hash": "readme"}
            return {"status": 404, "body": "", "body_hash": "missing"}

        with patch.object(wordpress, "_fetch", side_effect=fake_fetch), patch.object(wordpress, "is_baseline_match", return_value=False):
            inventory = wordpress.detect_wordpress_plugins("https://target.test", timeout=2)
        self.assertEqual(inventory["plugins"]["contact-form-7"]["version"], "5.3.1")
        self.assertIn("wp-contact-form-7.php", inventory["plugins"]["contact-form-7"]["source"])


class TestForminatorSelectInjectionProbe(unittest.TestCase):
    PAGE = (
        '<input type="hidden" name="form_id" value="7">'
        '<input type="hidden" name="forminator_nonce" value="abc123">'
        '<input type="file" name="upload-1">'
        '<select name="select-1"><option value="a">A</option></select>'
    )

    def _run(self, baseline_body, forged_body):
        from proofcms.modules.wordpress import cve_2026_15748 as module

        fake_form = [{"has_upload": True, "has_select": True, "form_ids": ["7"], "page_url": "https://target.test/quiz/"}]

        class FakeSession:
            def get(self, url, timeout=None):
                return {"status": 200, "body": TestForminatorSelectInjectionProbe.PAGE}

            def post_multipart(self, url, fields, files, headers=None, timeout=None):
                if "select-1[return]" in fields:
                    return {"status": 200, "body": forged_body}
                return {"status": 200, "body": baseline_body}

        with (
            patch.object(module, "discover_forms", return_value=fake_form),
            patch.object(module, "HttpSession", return_value=FakeSession()),
            patch.object(module, "rand_str", return_value="FORGE"),
        ):
            return module.run_aggressive_probe("https://target.test")

    def test_forged_field_error_confirms_injection(self):
        result = self._run(
            '{"success":false,"data":{"errors":[{"upload-1":"nope"}]}}',
            '{"success":false,"data":{"errors":[{"proofcmsFORGE":"Sorry, you are not allowed to upload this file type."}]}}',
        )
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertTrue(result.evidence["forged_error"])
        self.assertFalse(result.evidence["files_written"])

    def test_silent_forged_field_is_not_confirmed(self):
        result = self._run(
            '{"success":false,"data":{"errors":[{"upload-1":"nope"}]}}',
            '{"success":true,"data":{}}',
        )
        self.assertEqual(result.status, "NOT_CONFIRMED")

    def test_patched_version_skips_aggressive_probe(self):
        from proofcms.modules.wordpress import cve_2026_15748 as module

        with patch.object(module, "run_aggressive_probe") as probe:
            result = module.check(
                "https://target.test",
                run_exploit_check=True,
                exploit_mode="aggressive",
                plugins={"forminator": {"found": True, "version": "1.56.2"}},
            )
        self.assertEqual(result.status, "PATCHED")
        probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
