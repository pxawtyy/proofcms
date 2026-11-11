"""Unit tests for the Quick Playground CVE-2026-1830 passive module.

The module is intentionally passive-only: on a stock install the plugin
fatals the whole WordPress bootstrap (is_plugin_active() called at
plugins_loaded, undefined outside admin context), so the vulnerable REST
endpoint is unreachable without modifying the plugin. The module therefore
does version assessment only and never sends an upload.
"""

import unittest

from proofcms.modules.wordpress import cve_2026_1830


class TestQuickPlaygroundPassive(unittest.TestCase):
    def test_classify_boundaries(self):
        self.assertEqual(cve_2026_1830.classify_version("1.3.1"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_1830.classify_version("1.0"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_1830.classify_version("1.3.2"), "PATCHED")
        self.assertEqual(cve_2026_1830.classify_version("1.3.6"), "PATCHED")
        self.assertEqual(cve_2026_1830.classify_version(None), "DETECTED_VERSION_UNKNOWN")

    def test_detected_vulnerable_version(self):
        result = cve_2026_1830.check(
            "https://target.test",
            plugins={"quick-playground": {"found": True, "version": "1.3.1", "source": "readme.txt"}},
        )
        self.assertEqual(result.status, "LIKELY_VULNERABLE")
        self.assertIn("bootstrap", result.detail)

    def test_detected_fixed_version(self):
        result = cve_2026_1830.check(
            "https://target.test",
            plugins={"quick-playground": {"found": True, "version": "1.3.2", "source": "readme.txt"}},
        )
        self.assertEqual(result.status, "PATCHED")

    def test_missing_plugin(self):
        result = cve_2026_1830.check("https://target.test", plugins={})
        self.assertEqual(result.status, "NOT_DETECTED")

    def test_exploit_check_stays_passive(self):
        result = cve_2026_1830.check(
            "https://target.test",
            run_exploit_check=True,
            plugins={"quick-playground": {"found": True, "version": "1.3.1", "source": "readme.txt"}},
        )
        self.assertEqual(result.status, "LIKELY_VULNERABLE")
        self.assertFalse(result.exploit_ran)
        self.assertFalse(result.exploit_available)


if __name__ == "__main__":
    unittest.main()
