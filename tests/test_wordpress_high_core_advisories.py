import unittest

from proofcms.modules.wordpress import cve_2024_4439, cve_2026_64638, wpvdb_5e9804e5, wpvdb_aa354358, wpvdb_df1ca42d


class TestWordPressHighCoreAdvisories(unittest.TestCase):
    def test_cve_2024_4439_boundaries_and_poc(self):
        self.assertEqual(cve_2024_4439.classify_version("6.5.1"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2024_4439.classify_version("6.5.2"), "PATCHED")
        self.assertIn("autofocus", cve_2024_4439.metadata()["poc"])

    def test_cve_2026_64638_boundaries(self):
        self.assertEqual(cve_2026_64638.classify_version("7.0.2"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_64638.classify_version("7.0.3"), "PATCHED")
        self.assertEqual(cve_2026_64638.check("https://target.test", "7.0.2").vulnerability_type, "Cross-Site Scripting (XSS)")

    def test_wpvdb_advisories_keep_distinct_identifiers(self):
        modules = (wpvdb_df1ca42d, wpvdb_aa354358, wpvdb_5e9804e5)
        ids = {module.CVE_ID for module in modules}
        self.assertEqual(len(ids), 3)
        self.assertEqual(wpvdb_df1ca42d.classify_version("6.4.12"), "LIKELY_VULNERABLE")
        self.assertEqual(wpvdb_df1ca42d.classify_version("6.4.13"), "PATCHED")
        self.assertEqual(wpvdb_aa354358.classify_version("6.4.10"), "LIKELY_VULNERABLE")
        self.assertEqual(wpvdb_5e9804e5.classify_version("6.4.2"), "LIKELY_VULNERABLE")


if __name__ == "__main__":
    unittest.main()
