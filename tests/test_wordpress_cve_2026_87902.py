import unittest
from unittest.mock import patch

from proofcms.modules.wordpress import cve_2026_87902 as module


class TestCVE202687902VersionPolicy(unittest.TestCase):
    def test_all_official_branch_boundaries(self):
        for branch, fixed in module.FIRST_FIXED_BY_BRANCH.items():
            with self.subTest(branch=branch):
                major, minor = branch.split(".")
                fixed_patch = int(fixed.rsplit(".", 1)[1])
                affected = f"{major}.{minor}.{fixed_patch - 1}"
                self.assertEqual(module.classify_version(affected), "LIKELY_VULNERABLE")
                self.assertEqual(module.classify_version(fixed), "PATCHED")

    def test_versions_outside_published_branches_are_not_affected(self):
        self.assertEqual(module.classify_version("4.6.30"), "NOT_AFFECTED")
        self.assertEqual(module.classify_version("7.2.0"), "NOT_AFFECTED")

    def test_unknown_or_ambiguous_version_is_inconclusive(self):
        self.assertEqual(module.classify_version(None), "INCONCLUSIVE")
        self.assertEqual(module.classify_version("WordPress latest"), "INCONCLUSIVE")


class TestCVE202687902SafeProbe(unittest.TestCase):
    def test_candidate_double_encodes_slashes_and_traversal_periods(self):
        candidate = module._encoded_candidate("wp-links-opml", 1)
        self.assertEqual(candidate, "templates%252F%252E%252E%252Fwp-links-opml")

    @staticmethod
    def _response(status=200, body=""):
        return {"status": status, "body": body, "body_hash": "hash"}

    def test_differential_opml_response_confirms_lfi(self):
        def fake_request(url, method="GET", **kwargs):
            if "rest_route=" in url:
                return self._response(body='[{"id":2}]')
            body = kwargs.get("data", "")
            if "wp-links-opml" in body and "%252F" in body:
                return self._response(body='<?xml version="1.0"?><opml><head><title>WordPress Links</title></head></opml>')
            return self._response(body="normal page")

        with patch.object(module, "request", side_effect=fake_request):
            result = module.run_safe_probe("http://target", timeout=1)

        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertTrue(result.exploit_ran)

    def test_matching_control_cannot_confirm_lfi(self):
        def fake_request(url, method="GET", **kwargs):
            if "rest_route=" in url:
                return self._response(body='[{"id":2}]')
            return self._response(body='<?xml version="1.0"?><opml><head><title>WordPress Links</title></head></opml>')

        with patch.object(module, "request", side_effect=fake_request):
            result = module.run_safe_probe("http://target", timeout=1)

        self.assertEqual(result.status, "NOT_CONFIRMED")

    def test_invalid_rest_payload_falls_back_to_default_page(self):
        with patch.object(module, "request", return_value=self._response(body="not json")):
            self.assertEqual(module._discover_page_ids("http://target", 1, None), [2])

    def test_check_skips_probe_for_patched_version(self):
        with patch.object(module, "run_safe_probe") as probe:
            result = module.check(
                "http://target",
                "7.1.2",
                run_exploit_check=True,
                exploit_mode="safe",
            )
        self.assertEqual(result.status, "PATCHED")
        probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
