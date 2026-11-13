import base64
import json
import unittest
import urllib.parse
from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_57830, cve_2026_78079


class FakeHelixClient:
    def __init__(self, state):
        self.state = state

    def get(self, url, **kwargs):
        if "component/users/login" in url:
            return {
                "status": 200,
                "body": '<input type="hidden" name="0123456789abcdef0123456789abcdef" value="1">',
                "headers": {},
                "final_url": url,
            }
        return {"status": 200, "body": "<html>home</html>", "headers": {}, "final_url": url}

    def request(self, url, **kwargs):
        if "task=user.login" in url:
            return {
                "status": 303,
                "headers": {"Location": "https://target.test/index.php/component/users/profile"},
                "body": "",
                "final_url": url,
            }
        if "helixreturn" in url:
            encoded = url.split("helixreturn=", 1)[1]
            destination = base64.b64decode(urllib.parse.unquote(encoded)).decode()
            if self.state.get("vulnerable"):
                return {"status": 303, "headers": {"Location": destination}, "body": "", "final_url": url}
            return {"status": 200, "headers": {}, "body": "<html>home</html>", "final_url": url}
        return {"status": 200, "headers": {}, "body": "", "final_url": url}


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
        with patch.object(cve_2026_78079, "HttpClient", side_effect=lambda *a, **k: FakeHelixClient({"vulnerable": True})):
            result = cve_2026_78079.run_safe_probe(
                "https://target.test", username="admin", password="pw"
            )
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertEqual(result.evidence["location"], result.evidence["destination"])

    def test_patched_helix_does_not_confirm(self):
        with patch.object(cve_2026_78079, "HttpClient", side_effect=lambda *a, **k: FakeHelixClient({"vulnerable": False})):
            result = cve_2026_78079.run_safe_probe(
                "https://target.test", username="admin", password="pw"
            )
        self.assertEqual(result.status, "NOT_CONFIRMED")

    def test_missing_credentials_blocks(self):
        result = cve_2026_78079.run_safe_probe("https://target.test")
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")

    def test_unrelated_redirect_is_not_confirmed(self):
        class UnrelatedClient(FakeHelixClient):
            def request(self, url, **kwargs):
                if "helixreturn" in url:
                    return {
                        "status": 302,
                        "headers": {"Location": "https://target.test/login"},
                        "body": "",
                        "final_url": url,
                    }
                return super().request(url, **kwargs)

        with patch.object(cve_2026_78079, "HttpClient", side_effect=lambda *a, **k: UnrelatedClient({})):
            result = cve_2026_78079.run_safe_probe(
                "https://target.test", username="admin", password="pw"
            )
        self.assertEqual(result.status, "NOT_CONFIRMED")

    def test_transport_failure_is_error(self):
        class DeadClient(FakeHelixClient):
            def get(self, url, **kwargs):
                return {"status": 0, "body": "", "headers": {}, "error": {"type": "URLError", "message": "timed out"}}

        with patch.object(cve_2026_78079, "HttpClient", side_effect=lambda *a, **k: DeadClient({})):
            result = cve_2026_78079.run_safe_probe(
                "https://target.test", username="admin", password="pw"
            )
        self.assertEqual(result.status, "ERROR")

    def test_existing_file_deletion_module_has_correct_identity(self):
        meta = cve_2026_57830.metadata()
        self.assertIn("file deletion", meta["name"])
        self.assertIn("2.2.6", meta["affected_rule"])

    def test_helix_version_outside_range_is_not_affected_and_skips_probe(self):
        result = cve_2026_57830.check(
            "https://target.test",
            run_exploit_check=True,
            plugins={"helixultimate": {"found": True, "version": "2.2.10.0.1"}},
        )
        self.assertEqual(result.status, "NOT_AFFECTED")
        self.assertFalse(result.exploit_ran)

    def test_helix_generic_joomla_success_is_not_confirmation(self):
        response = {
            "status": 200,
            "body": '{"success":true,"message":null,"data":null}',
            "redirected": False,
        }
        with (
            patch.object(cve_2026_57830.HttpClient, "request", return_value=response),
            patch.object(cve_2026_57830, "find_anon_csrf_token", return_value=("a" * 32, "/")),
        ):
            result = cve_2026_57830.run_safe_probe("https://target.test")
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertFalse(result.evidence["handler_reached"])

    def test_missing_token_on_reachable_target_is_blocked_external(self):
        response = {"status": 200, "redirected": False, "body": "<html>no token</html>"}
        with (
            patch.object(cve_2026_57830.HttpClient, "request", return_value=response),
            patch.object(cve_2026_57830, "find_anon_csrf_token", return_value=(None, None)),
        ):
            result = cve_2026_57830.run_safe_probe("https://target.test")
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")

    def test_transport_failure_is_error_for_file_deletion(self):
        response = {"status": 0, "redirected": False, "body": "", "error": {"type": "URLError", "message": "timed out"}}
        with patch.object(cve_2026_57830.HttpClient, "request", return_value=response):
            result = cve_2026_57830.run_safe_probe("https://target.test")
        self.assertEqual(result.status, "ERROR")

    def test_helix_confirms_listing_and_bounded_webroot_escape(self):
        def listing(path, folders, images):
            return {
                "status": 200,
                "redirected": False,
                "body": json.dumps(
                    {
                        "status": True,
                        "output": '<div id="helix-ultimate-media-manager"></div>',
                        "path": path,
                        "folders": folders,
                        "images": images,
                    }
                ),
            }

        responses = [
            {"status": 200, "redirected": False, "body": "<html>home</html>"},
            {"status": 200, "redirected": False, "body": '{"success":true,"data":null}'},
            listing("/images", ["banners"], ["/srv/www/images/a.png"]),
            listing("/", ["plugins", "images"], []),
            listing("/", ["plugins", "images"], []),
        ]
        with (
            patch.object(cve_2026_57830.HttpClient, "request", side_effect=responses),
            patch.object(cve_2026_57830, "find_anon_csrf_token", return_value=("a" * 32, "/")),
        ):
            result = cve_2026_57830.run_safe_probe("https://target.test")
        self.assertEqual(result.status, "VULNERABLE")
        self.assertTrue(result.evidence["webroot_boundary_escape"])
        self.assertTrue(result.evidence["absolute_paths_disclosed"])
        self.assertIn("File deletion was not tested", result.detail)


if __name__ == "__main__":
    unittest.main()
