import unittest
from unittest.mock import patch

from proofcms.modules.wordpress import cve_2026_60137 as module


class TestCVE202660137VersionPolicy(unittest.TestCase):
    def test_official_branch_boundaries(self):
        for branch, fixed in module.FIRST_FIXED_BY_BRANCH.items():
            with self.subTest(branch=branch):
                major, minor = branch.split(".")
                fixed_patch = int(fixed.rsplit(".", 1)[1])
                self.assertEqual(module.classify_version(f"{major}.{minor}.{fixed_patch - 1}"), "LIKELY_VULNERABLE")
                self.assertEqual(module.classify_version(fixed), "PATCHED")

    def test_versions_outside_published_branches_are_not_affected(self):
        self.assertEqual(module.classify_version("6.7.9"), "NOT_AFFECTED")
        self.assertEqual(module.classify_version("7.1.0"), "NOT_AFFECTED")

    def test_unknown_version_is_inconclusive(self):
        self.assertEqual(module.classify_version(None), "INCONCLUSIVE")


class TestCVE202660137SafeProbe(unittest.TestCase):
    def test_payload_uses_only_boolean_sleep_condition(self):
        payload = module._batch_payload("1=1", 0.35).decode()
        self.assertIn("author_exclude", payload)
        self.assertIn("SELECT+IF%28%281%3D1%29%2CSLEEP%280.350%29%2C0%29", payload)
        self.assertNotIn("users", payload)

    def test_timing_differential_confirms_sqli(self):
        def fake_probe(target, condition, *args, **kwargs):
            return (0.50 if condition == "1=1" else 0.10), {"status": 200}

        with patch.object(module, "_timed_probe", side_effect=fake_probe):
            result = module.run_safe_probe("http://target")

        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")

    def test_no_timing_differential_is_not_confirmed(self):
        with patch.object(module, "_timed_probe", return_value=(0.11, {"status": 200})):
            result = module.run_safe_probe("http://target")
        self.assertEqual(result.status, "NOT_CONFIRMED")

    def test_transport_timeout_cannot_confirm_sqli(self):
        def fake_probe(target, condition, *args, **kwargs):
            return (0.50 if condition == "1=1" else 0.10), {"status": 0 if condition == "1=1" else 200}

        with patch.object(module, "_timed_probe", side_effect=fake_probe):
            result = module.run_safe_probe("http://target")
        self.assertEqual(result.status, "NOT_CONFIRMED")

    def test_active_probe_skipped_on_68_without_stock_delivery(self):
        with patch.object(module, "run_safe_probe") as probe:
            result = module.check("http://target", "6.8.5", run_exploit_check=True)
        self.assertEqual(result.status, "LIKELY_VULNERABLE")
        probe.assert_not_called()

    def test_active_probe_skipped_for_patched_version(self):
        with patch.object(module, "run_safe_probe") as probe:
            result = module.check("http://target", "7.0.2", run_exploit_check=True)
        self.assertEqual(result.status, "PATCHED")
        probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
