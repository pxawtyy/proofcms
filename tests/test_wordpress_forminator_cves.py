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


if __name__ == "__main__":
    unittest.main()
