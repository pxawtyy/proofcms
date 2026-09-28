import unittest
from unittest.mock import patch

from proofcms.chains.wp2shell import aggregate
from proofcms.modules.wordpress import cve_2026_63030 as module


class TestCVE202663030VersionPolicy(unittest.TestCase):
    def test_official_branch_boundaries(self):
        self.assertEqual(module.classify_version("6.9.4"), "LIKELY_VULNERABLE")
        self.assertEqual(module.classify_version("6.9.5"), "PATCHED")
        self.assertEqual(module.classify_version("7.0.1"), "LIKELY_VULNERABLE")
        self.assertEqual(module.classify_version("7.0.2"), "PATCHED")

    def test_other_branches_are_not_affected(self):
        self.assertEqual(module.classify_version("6.8.5"), "NOT_AFFECTED")
        self.assertEqual(module.classify_version("7.1.0"), "NOT_AFFECTED")


class TestCVE202663030SafeProbe(unittest.TestCase):
    def test_batch_route_signature(self):
        response = {"status": 400, "body": '{"code":"rest_missing_callback_param"}'}
        with patch.object(module, "request", return_value=response):
            self.assertTrue(module.batch_route_available("http://target"))

    def test_combined_timing_proof_confirms_delivery_path(self):
        combined = module.Finding(
            cve="CVE-2026-60137",
            name="SQLi",
            status="VULNERABLE",
            confidence="CONFIRMED",
            proof_url="http://target/?rest_route=/batch/v1",
            detail="timing confirmed",
        )
        with (
            patch.object(module, "batch_route_available", return_value=True),
            patch.object(module.cve_2026_60137, "run_safe_probe", return_value=combined),
        ):
            result = module.run_safe_probe("http://target")
        self.assertEqual(result.status, "VULNERABLE")
        self.assertIn("No data was extracted", result.detail)

    def test_patched_version_skips_active_probe(self):
        with patch.object(module, "run_safe_probe") as probe:
            result = module.check("http://target", "7.0.2", run_exploit_check=True)
        self.assertEqual(result.status, "PATCHED")
        probe.assert_not_called()


class TestWp2ShellChain(unittest.TestCase):
    @staticmethod
    def results(first, second):
        return [
            {"cve": "CVE-2026-63030", "status": first},
            {"cve": "CVE-2026-60137", "status": second},
        ]

    def test_confirmed_component_makes_positive_chain_confirmed(self):
        result = aggregate(self.results("VULNERABLE", "LIKELY_VULNERABLE"))
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertEqual(result["confidence"], "CONFIRMED")

    def test_two_passive_components_are_likely(self):
        result = aggregate(self.results("LIKELY_VULNERABLE", "LIKELY_VULNERABLE"))
        self.assertEqual(result["status"], "LIKELY_VULNERABLE")

    def test_patched_component_breaks_chain(self):
        result = aggregate(self.results("PATCHED", "LIKELY_VULNERABLE"))
        self.assertEqual(result["status"], "NOT_AFFECTED")


if __name__ == "__main__":
    unittest.main()
