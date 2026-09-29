import unittest
from unittest.mock import patch

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
        plugins["nrframework"]["version"] = "4.9.62"
        self.assertEqual(
            cve_2026_21627.check("https://target.test", plugins=plugins).status,
            "NOT_AFFECTED",
        )

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

    def test_safe_probe_uploads_verifies_and_removes_own_marker(self):
        class FakeClient:
            def __init__(self, **kwargs):
                self.marker = ""
                self.proof_requests = 0

            def request(self, url, **kwargs):
                if "/images/" in url:
                    self.proof_requests += 1
                    if self.proof_requests == 1:
                        return {"status": 200, "body": self.marker}
                    return {"status": 404, "body": ""}
                return {"status": 200, "body": '{"error":false}'}

            def post_multipart(self, url, fields, files, **kwargs):
                self.marker = files["file"][1].decode()
                return {
                    "status": 200,
                    "body": (
                        '{"error":false,"file_name":"ignored",'
                        '"file":"/srv/www/images/abc123_proof.txt"}'
                    ),
                }

        with (
            patch.object(cve_2026_21627, "HttpClient", FakeClient),
            patch.object(
                cve_2026_21627,
                "find_anon_csrf_token",
                return_value=("a" * 32, "https://target.test/"),
            ),
        ):
            result = cve_2026_21627.run_safe_probe("https://target.test")
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertIsNone(result.uploaded_filename)

    def test_active_probe_runs_for_detected_pre_range_framework(self):
        plugins = {"nrframework": {"found": True, "version": "4.9.62"}}
        confirmed = cve_2026_21627._finding("VULNERABLE", "CONFIRMED", "proof", exploit_ran=True)
        with patch.object(cve_2026_21627, "run_safe_probe", return_value=confirmed) as probe:
            result = cve_2026_21627.check(
                "https://target.test",
                plugins=plugins,
                run_exploit_check=True,
                exploit_mode="safe",
            )
        probe.assert_called_once()
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.component_version, "4.9.62")


if __name__ == "__main__":
    unittest.main()
