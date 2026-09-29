import unittest
from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_57830, cve_2026_78079


class TestCVE202678079(unittest.TestCase):
    def test_version_boundaries(self):
        self.assertEqual(cve_2026_78079.classify_version("2.2.9"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_78079.classify_version("2.2.10"), "PATCHED")
        self.assertEqual(cve_2026_78079.classify_version(None), "INCONCLUSIVE")

    def test_passive_detection_uses_helix_inventory(self):
        result = cve_2026_78079.check(
            "https://target.test",
            "5.3.0",
            plugins={"helixultimate": {"found": True, "version": "2.2.9"}},
        )
        self.assertEqual(result.status, "LIKELY_VULNERABLE")
        self.assertEqual(result.component_version, "2.2.9")

    def test_safe_probe_confirms_exact_external_redirect_without_following(self):
        test_case = self

        def fake_request(client, url, **kwargs):
            encoded = url.split("helixreturn=", 1)[1]
            import base64
            import urllib.parse

            destination = base64.b64decode(urllib.parse.unquote(encoded)).decode()
            test_case.assertFalse(kwargs["follow_redirects"])
            return {"status": 302, "headers": {"Location": destination}, "body": ""}

        with patch.object(cve_2026_78079.HttpClient, "request", new=fake_request):
            result = cve_2026_78079.run_safe_probe("https://target.test")
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")

    def test_unrelated_redirect_is_not_confirmed(self):
        response = {"status": 302, "headers": {"Location": "https://target.test/login"}, "body": ""}
        with patch.object(cve_2026_78079.HttpClient, "request", return_value=response):
            result = cve_2026_78079.run_safe_probe("https://target.test")
        self.assertEqual(result.status, "NOT_CONFIRMED")

    def test_existing_file_deletion_module_has_correct_identity(self):
        meta = cve_2026_57830.metadata()
        self.assertIn("file deletion", meta["name"])
        self.assertIn("2.2.6", meta["affected_rule"])


if __name__ == "__main__":
    unittest.main()
