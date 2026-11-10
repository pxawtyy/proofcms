"""Unit tests for the Helix Ultimate CVE-2026-57830 safe probe (fixed endpoint)."""
import json
import unittest
from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_57830


def _listing(path="/images", folders=("banners",), images=("logo.png",)):
    return {
        "status": True,
        "output": '<div id="helix-ultimate-media-manager">listing</div>',
        "folders": list(folders),
        "images": list(images),
        "path": path,
    }


class FakeClient:
    def __init__(self, listing):
        self.listing = listing
        self.urls = []

    def request(self, url, **kwargs):
        self.urls.append(url)
        if url.rstrip("/").endswith("example.test") or url == "https://target.test/":
            return {
                "status": 200,
                "body": '<form><input type="hidden" name="0123456789abcdef0123456789abcdef" value="1"></form>',
                "headers": {},
            }
        data = kwargs.get("data", "")
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="replace")
        if "action=view-media" in url:
            return {
                "status": 200,
                "body": json.dumps(self.listing),
                "headers": {},
            }
        return {
            "status": 200,
            "body": '{"success":true,"message":null,"messages":null,"data":[]}',
            "headers": {},
        }


class TestHelixUltimateEndpoint(unittest.TestCase):
    def test_ajax_base_routes_through_helix_param(self):
        self.assertIn("helix=ultimate", cve_2026_57830.AJAX_BASE)
        self.assertIn("action=view-media", cve_2026_57830.AJAX_ENDPOINT)
        self.assertNotIn("plugin=helixultimate", cve_2026_57830.AJAX_BASE)

    def test_parse_listing_accepts_helix_signature(self):
        parsed = cve_2026_57830._parse_listing(
            {"status": 200, "redirected": False, "body": json.dumps(_listing())}
        )
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["folder_count"], 1)

    def test_parse_listing_rejects_empty_com_ajax_envelope(self):
        parsed = cve_2026_57830._parse_listing(
            {"status": 200, "redirected": False,
             "body": '{"success":true,"message":null,"messages":null,"data":[]}'}
        )
        self.assertIsNone(parsed)


class TestHelixUltimateSafeProof(unittest.TestCase):
    def test_media_listing_confirms_vulnerable(self):
        client = FakeClient(_listing())
        with (
            patch.object(cve_2026_57830, "HttpClient", return_value=client),
            patch.object(
                cve_2026_57830, "find_anon_csrf_token",
                return_value=("0123456789abcdef0123456789abcdef", "homepage"),
            )
        ):
            result = cve_2026_57830.run_safe_probe("https://target.test", timeout=2)
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertTrue(result.exploit_ran)
        self.assertTrue(any("helix=ultimate" in u for u in client.urls))

    def test_missing_token_blocks_externally(self):
        with (
            patch.object(cve_2026_57830, "HttpClient", return_value=FakeClient(_listing())),
            patch.object(cve_2026_57830, "find_anon_csrf_token", return_value=(None, "homepage")),
        ):
            result = cve_2026_57830.run_safe_probe("https://target.test", timeout=2)
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")


if __name__ == "__main__":
    unittest.main()
