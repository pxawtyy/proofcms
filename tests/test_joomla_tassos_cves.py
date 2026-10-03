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
                if kwargs.get("method") == "POST":
                    body = kwargs["data"].decode()
                    marker_start = body.index("ProofCMS CVE-2026-21627 safe proof")
                    self.marker = body[marker_start:].split("\r\n", 1)[0]
                    return {
                        "status": 200,
                        "body": (
                            '{"error":false,"file_name":"ignored",'
                            '"file":"/srv/www/images/abc123_proof.txt"}'
                        ),
                    }
                if url.rstrip("/") == "https://target.test":
                    return {
                        "status": 200,
                        "body": f'<script>"csrf.token":"{"a" * 32}"</script>',
                        "final_url": "https://target.test/",
                    }
                return {"status": 200, "body": '{"error":false}'}

        with patch.object(cve_2026_21627, "HttpClient", FakeClient):
            result = cve_2026_21627.run_safe_probe("https://target.test")
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertIsNone(result.uploaded_filename)

    def test_decodes_framework_base64_upload_response(self):
        import base64

        path = "/srv/www/images/abc123_proof.txt"
        name = "abc123_proof.txt"
        result = cve_2026_21627._stored_filename(
            {
                "file": base64.b64encode(path.encode()).decode(),
                "file_name": base64.b64encode(name.encode()).decode(),
            }
        )
        self.assertEqual(result, (name, path))

    def test_empty_valid_preflight_uses_invalid_token_differential(self):
        class FakeClient:
            def __init__(self, **kwargs):
                pass

            def request(self, url, **kwargs):
                if kwargs.get("method") == "POST":
                    return {"status": 200, "body": "", "redirected": False}
                if "plugin=proofcmsnosuchplugin" in url:
                    return {"status": 200, "body": "", "redirected": False}
                if "plugin=nrframework" in url and "task=include" not in url:
                    return {"status": 200, "body": "JINVALID_TOKEN", "redirected": False}
                if "plugin=nrframework" in url and "task=include" in url:
                    return {"status": 200, "body": "", "redirected": False}
                return {
                    "status": 200,
                    "body": f'<input name="{"a" * 32}" value="1">',
                    "final_url": "https://target.test/",
                    "redirected": False,
                }

        with patch.object(cve_2026_21627, "HttpClient", FakeClient):
            result = cve_2026_21627.run_safe_probe("https://target.test")
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertTrue(result.exploit_ran)
        self.assertTrue(result.evidence["component_present"])
        self.assertTrue(result.evidence["token_accepted"])
        self.assertFalse(result.evidence["write_reported"])

    def test_csrf_candidates_use_only_frontend_session_tokens(self):
        class FakeClient:
            def request(self, url, **kwargs):
                token = "a" * 32
                return {"status": 200, "body": f'<input name="{token}" value="1">'}

        candidates = cve_2026_21627._csrf_candidates(
            FakeClient(),
            "https://target.test",
            "https://target.test/",
            2,
        )
        self.assertTrue(candidates)
        self.assertTrue(all("/administrator" not in source for _, source in candidates))

    def test_active_probe_skips_detected_pre_range_framework(self):
        plugins = {"nrframework": {"found": True, "version": "4.9.62"}}
        confirmed = cve_2026_21627._finding("VULNERABLE", "CONFIRMED", "proof", exploit_ran=True)
        with patch.object(cve_2026_21627, "run_safe_probe", return_value=confirmed) as probe:
            result = cve_2026_21627.check(
                "https://target.test",
                plugins=plugins,
                run_exploit_check=True,
                exploit_mode="safe",
            )
        probe.assert_not_called()
        self.assertEqual(result.status, "NOT_AFFECTED")
        self.assertEqual(result.component_version, "4.9.62")
        self.assertIn("separate backend session", result.detail)


if __name__ == "__main__":
    unittest.main()
