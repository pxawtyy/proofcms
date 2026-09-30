import unittest
from unittest.mock import patch

from proofcms.detectors import wordpress
from proofcms.modules.wordpress import (
    cve_2020_25213,
    cve_2023_3460,
    cve_2023_32243,
    cve_2024_10924,
    cve_2024_28000,
)


class TestCriticalPluginVersionPolicies(unittest.TestCase):
    def test_boundaries(self):
        cases = (
            (cve_2020_25213, "5.9", "NOT_AFFECTED"),
            (cve_2020_25213, "6.8", "LIKELY_VULNERABLE"),
            (cve_2020_25213, "6.9", "PATCHED"),
            (cve_2023_32243, "5.3.9", "NOT_AFFECTED"),
            (cve_2023_32243, "5.7.1", "LIKELY_VULNERABLE"),
            (cve_2023_32243, "5.7.2", "PATCHED"),
            (cve_2023_3460, "2.6.6", "LIKELY_VULNERABLE"),
            (cve_2023_3460, "2.6.7", "PATCHED"),
            (cve_2024_10924, "8.3.0", "NOT_AFFECTED"),
            (cve_2024_10924, "9.1.1.1", "LIKELY_VULNERABLE"),
            (cve_2024_10924, "9.1.2", "PATCHED"),
            (cve_2024_28000, "1.8.9", "NOT_AFFECTED"),
            (cve_2024_28000, "6.3.0.1", "LIKELY_VULNERABLE"),
            (cve_2024_28000, "6.4", "PATCHED"),
        )
        for module, version, expected in cases:
            with self.subTest(cve=module.CVE_ID, version=version):
                self.assertEqual(module.classify_version(version), expected)

    def test_unknown_and_missing_plugin_states(self):
        modules = (
            cve_2020_25213,
            cve_2023_32243,
            cve_2023_3460,
            cve_2024_10924,
            cve_2024_28000,
        )
        for module in modules:
            with self.subTest(cve=module.CVE_ID):
                self.assertEqual(module.classify_version(None), "DETECTED_VERSION_UNKNOWN")
                self.assertEqual(module.check("https://target.test", plugins={}).status, "NOT_DETECTED")


class TestCriticalPluginDiscovery(unittest.TestCase):
    def test_known_plugins_are_probed_and_markers_prevent_custom_200_false_positives(self):
        def fake_fetch(url, timeout, proxy=None):
            if url.endswith("/wp-content/plugins/litespeed-cache/readme.txt"):
                return {"status": 200, "body": "=== LiteSpeed Cache ===\nStable tag: 6.3.0.1", "body_hash": "lsc"}
            return {"status": 200, "body": "=== unrelated plugin ===\nStable tag: 1.2.3", "body_hash": "generic"}

        with (
            patch.object(wordpress, "_fetch", side_effect=fake_fetch),
            patch.object(wordpress, "is_baseline_match", return_value=False),
        ):
            inventory = wordpress.detect_wordpress_plugins("https://target.test", timeout=2)

        self.assertEqual(inventory["plugins"]["litespeed-cache"]["version"], "6.3.0.1")
        self.assertNotIn("ultimate-member", inventory["plugins"])
        self.assertNotIn("wp-file-manager", inventory["plugins"])


if __name__ == "__main__":
    unittest.main()
