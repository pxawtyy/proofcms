import unittest

from proofcms.modules.joomla import cve_2024_40744, cve_2026_21627


class TestJoomlaTassosCVEs(unittest.TestCase):
    def test_convert_forms_upload_version_boundary(self):
        self.assertEqual(cve_2024_40744.classify_version("4.4.7"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2024_40744.classify_version("4.4.8"), "PATCHED")

    def test_framework_range_boundaries(self):
        plugins = {"nrframework": {"found": True, "version": "6.0.37"}}
        self.assertEqual(cve_2026_21627.check("https://target.test", plugins=plugins).status, "LIKELY_VULNERABLE")
        plugins["nrframework"]["version"] = "6.0.38"
        self.assertEqual(cve_2026_21627.check("https://target.test", plugins=plugins).status, "PATCHED")

    def test_affected_bundled_product_is_reported(self):
        plugins = {"google_structured_data": {"found": True, "version": "6.1.0"}}
        result = cve_2026_21627.check("https://target.test", plugins=plugins)
        self.assertEqual(result.status, "LIKELY_VULNERABLE")
        self.assertIn("Google Structured Data 6.1.0", result.detail)

    def test_direct_patched_framework_overrides_old_product_proxy(self):
        plugins = {
            "nrframework": {"found": True, "version": "6.0.38"},
            "convertforms": {"found": True, "version": "5.1.0"},
        }
        self.assertEqual(cve_2026_21627.check("https://target.test", plugins=plugins).status, "PATCHED")

    def test_mailchimp_without_published_product_range_is_inconclusive(self):
        plugins = {"mailchimp_auto_subscribe": {"found": True, "version": "5.1.0"}}
        result = cve_2026_21627.check("https://target.test", plugins=plugins)
        self.assertEqual(result.status, "INCONCLUSIVE")
        self.assertIn("MailChimp Auto-Subscribe", result.detail)


if __name__ == "__main__":
    unittest.main()
