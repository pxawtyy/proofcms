import unittest
import urllib.parse
from unittest.mock import patch

from proofcms.modules.wordpress import cve_2024_4439, cve_2026_64638, wpvdb_5e9804e5, wpvdb_aa354358, wpvdb_df1ca42d


class TestWordPressHighCoreAdvisories(unittest.TestCase):
    def test_cve_2024_4439_boundaries_and_poc(self):
        self.assertEqual(cve_2024_4439.classify_version("6.5.1"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2024_4439.classify_version("6.5.2"), "PATCHED")
        self.assertIn("autofocus", cve_2024_4439.metadata()["poc"])

    def test_cve_2026_64638_boundaries(self):
        self.assertEqual(cve_2026_64638.classify_version("7.0.2"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_64638.classify_version("7.0.3"), "PATCHED")
        result = cve_2026_64638.check("https://target.test", "7.0.2")
        self.assertEqual(result.vulnerability_type, "Cross-Site Scripting (XSS)")
        self.assertEqual(result.status, "NOT_CONFIRMED")

    def test_cve_2026_64638_safe_parser_differential(self):
        def fake_request(url, method="GET", **kwargs):
            if method == "GET":
                return {"status": 200, "body": '<form id="loginform"></form>'}
            value = urllib.parse.parse_qs(kwargs["data"])["log"][0]
            marker = value.split("id=", 1)[1].split()[0]
            return {"status": 200, "body": f'<area id="{marker}" href="/">'}

        with patch.object(cve_2026_64638, "request", side_effect=fake_request):
            result = cve_2026_64638.check(
                "https://target.test", "7.0.2", run_exploit_check=True, exploit_mode="safe"
            )

        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertTrue(result.evidence["raw_area_tag"])

    def test_cve_2026_64638_blocked_baseline_sends_no_proof(self):
        with patch.object(cve_2026_64638, "request", return_value={"status": 403, "body": "Forbidden"}) as request:
            result = cve_2026_64638.run_safe_probe("https://target.test", "7.0.2")

        self.assertEqual(result.status, "BLOCKED_EXTERNAL")
        self.assertEqual(request.call_count, 1)
        self.assertFalse(result.evidence["proof_sent"])

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
