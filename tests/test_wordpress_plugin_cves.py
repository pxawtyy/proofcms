import unittest
from unittest.mock import patch

from proofcms.detectors import wordpress
from proofcms.modules.wordpress import cve_2020_35489, cve_2023_28121, cve_2026_6692, cve_2026_18781


class TestWordPressPluginVersionPolicies(unittest.TestCase):
    def test_contact_form_7_boundary(self):
        self.assertEqual(cve_2020_35489.classify_version("5.3.1"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2020_35489.classify_version("5.3.2"), "PATCHED")

    def test_drag_drop_upload_boundary(self):
        self.assertEqual(cve_2026_18781.classify_version("1.3.9.8"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_18781.classify_version("1.3.9.9"), "PATCHED")

    def test_slider_revolution_range(self):
        self.assertEqual(cve_2026_6692.classify_version("6.7.0"), "NOT_AFFECTED")
        self.assertEqual(cve_2026_6692.classify_version("7.0.10"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_6692.classify_version("7.0.11"), "PATCHED")

    def test_woopayments_branch_boundaries(self):
        cases = {
            "4.7.9": "NOT_AFFECTED",
            "4.8.1": "LIKELY_VULNERABLE",
            "4.8.2": "PATCHED",
            "5.6.1": "LIKELY_VULNERABLE",
            "5.6.2": "PATCHED",
            "6.2.1": "LIKELY_VULNERABLE",
            "6.2.2": "PATCHED",
            "6.3.0": "PATCHED",
            "6.3.1": "LIKELY_VULNERABLE",
            "6.3.2": "PATCHED",
            "6.4.0": "PATCHED",
        }
        for version, expected in cases.items():
            with self.subTest(version=version):
                self.assertEqual(cve_2023_28121.classify_version(version), expected)

    def test_passive_plugin_finding_uses_inventory(self):
        result = cve_2020_35489.check(
            "https://target.test",
            "7.0.1",
            run_exploit_check=False,
            plugins={"contact-form-7": {"found": True, "version": "5.3.1"}},
        )
        self.assertEqual(result.status, "LIKELY_VULNERABLE")
        self.assertEqual(result.component_version, "5.3.1")


class TestWooPaymentsSafeProbe(unittest.TestCase):
    def test_read_only_header_probe_confirms_impersonation(self):
        response = {
            "status": 200,
            "body": '{"id":1,"capabilities":{"administrator":true}}',
        }
        with patch.object(cve_2023_28121, "request", return_value=response) as send:
            result = cve_2023_28121.run_safe_probe("https://target.test")
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertEqual(send.call_args.kwargs["headers"]["X-WCPAY-PLATFORM-CHECKOUT-USER"], "1")
        self.assertIsNone(send.call_args.kwargs.get("data"))

    def test_rejected_header_is_not_confirmed(self):
        with patch.object(
            cve_2023_28121,
            "request",
            return_value={"status": 401, "body": '{"code":"rest_not_logged_in"}'},
        ):
            result = cve_2023_28121.run_safe_probe("https://target.test")
        self.assertEqual(result.status, "NOT_CONFIRMED")


class TestKnownPluginDiscovery(unittest.TestCase):
    def test_known_plugin_readme_is_probed_when_absent_from_homepage(self):
        def fake_fetch(url, timeout, proxy=None):
            if url.endswith("/wp-content/plugins/contact-form-7/readme.txt"):
                return {"status": 200, "body": "=== Contact Form 7 ===\nStable tag: 5.3.1", "body_hash": "cf7"}
            return {"status": 404, "body": "", "body_hash": "missing"}

        with (
            patch.object(wordpress, "_fetch", side_effect=fake_fetch),
            patch.object(wordpress, "is_baseline_match", return_value=False),
        ):
            inventory = wordpress.detect_wordpress_plugins("https://target.test", timeout=2)
        plugin = inventory["plugins"]["contact-form-7"]
        self.assertTrue(plugin["found"])
        self.assertEqual(plugin["version"], "5.3.1")

    def test_generic_readme_does_not_create_false_positive(self):
        response = {"status": 200, "body": "=== unrelated plugin ===\nStable tag: 1.2.3", "body_hash": "same"}
        with (
            patch.object(wordpress, "_fetch", return_value=response),
            patch.object(wordpress, "is_baseline_match", return_value=False),
        ):
            inventory = wordpress.detect_wordpress_plugins("https://target.test", timeout=2)
        self.assertNotIn("contact-form-7", inventory["plugins"])
        self.assertNotIn("woocommerce-payments", inventory["plugins"])

    def test_all_new_modules_accept_standard_cli_signature(self):
        modules = (cve_2020_35489, cve_2023_28121, cve_2026_6692, cve_2026_18781)
        for module in modules:
            with self.subTest(module=module.CVE_ID):
                result = module.check(
                    "https://target.test",
                    "7.0.1",
                    run_exploit_check=False,
                    plugins={},
                )
                self.assertEqual(result.status, "NOT_DETECTED")


if __name__ == "__main__":
    unittest.main()
