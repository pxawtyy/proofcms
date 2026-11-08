import unittest
from unittest.mock import patch

from proofcms.modules.wordpress import cve_2024_28000

ADMIN_JSON = (
    '{"id":1,"username":"admin","roles":["administrator"],'
    '"capabilities":{"administrator":true,"manage_options":true}}'
)


class TestLiteSpeedVersionPolicy(unittest.TestCase):
    def test_version_boundary(self):
        self.assertEqual(cve_2024_28000.classify_version("6.3.0.1"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2024_28000.classify_version("6.4"), "PATCHED")
        self.assertEqual(cve_2024_28000.classify_version("1.8"), "NOT_AFFECTED")
        self.assertEqual(cve_2024_28000.classify_version(None), "DETECTED_VERSION_UNKNOWN")


class TestPHPMTCompatibility(unittest.TestCase):
    def test_known_php_seeds(self):
        cases = {
            0: "iZfern",
            1: "Fp8eBd",
            530337: "yw2fNq",
            95767: "HNBzcx",
        }
        for seed, expected in cases.items():
            with self.subTest(seed=seed):
                self.assertEqual(cve_2024_28000._PHPMT(seed).rrand6(), expected)

    def test_seed_candidates_are_ordered_around_center(self):
        seeds = cve_2024_28000._seed_candidates(500000, 2)
        self.assertEqual(seeds, [500000, 500001, 499999, 500002, 499998])


class TestLiteSpeedKnownHash(unittest.TestCase):
    def test_known_hash_impersonates_admin(self):
        def fake_request(url, headers=None, timeout=None, proxy=None, **kwargs):
            cookie = (headers or {}).get("Cookie", "")
            if "litespeed_hash=yw2fNq" in cookie:
                return {"status": 200, "body": ADMIN_JSON}
            return {"status": 401, "body": '{"code":"rest_not_logged_in"}'}

        with patch.object(cve_2024_28000, "request", side_effect=fake_request):
            result = cve_2024_28000.run_aggressive_probe(
                "https://target.test",
                known_hash="yw2fNq",
            )
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertTrue(result.exploit_ran)

    def test_wrong_known_hash_is_not_confirmed(self):
        with patch.object(
            cve_2024_28000,
            "request",
            return_value={"status": 401, "body": '{"code":"rest_not_logged_in"}'},
        ):
            result = cve_2024_28000.run_aggressive_probe(
                "https://target.test",
                known_hash="wrong1",
            )
        self.assertEqual(result.status, "NOT_CONFIRMED")


class TestLiteSpeedSeedSearch(unittest.TestCase):
    def test_trigger_and_seed_search_confirm(self):
        with (
            patch.object(cve_2024_28000, "_trigger_crawler", return_value={"status": 200, "body": "0"}),
            patch.object(cve_2024_28000, "time") as fake_time,
            patch.object(
                cve_2024_28000,
                "_try_seeds",
                return_value=(680001, "ABC123", "https://target.test/proof"),
            ) as try_seeds,
        ):
            fake_time.time.side_effect = [1000.0, 1000.8]
            result = cve_2024_28000.run_aggressive_probe("https://target.test", seed_window_ms=10)
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        assert result.evidence is not None
        self.assertEqual(result.evidence["seed"], 680001)
        self.assertEqual(result.evidence["hash"], "ABC123")
        seeds = try_seeds.call_args.args[1]
        self.assertIn(680000, seeds)

    def test_no_seed_match_is_not_confirmed(self):
        with (
            patch.object(cve_2024_28000, "_trigger_crawler", return_value={"status": 200, "body": "0"}),
            patch.object(cve_2024_28000, "time") as fake_time,
            patch.object(cve_2024_28000, "_try_seeds", return_value=None),
        ):
            fake_time.time.side_effect = [1000.0, 1000.8]
            result = cve_2024_28000.run_aggressive_probe("https://target.test", seed_window_ms=10)
        self.assertEqual(result.status, "NOT_CONFIRMED")


class TestLiteSpeedCheckGate(unittest.TestCase):
    def test_patched_version_skips_probe(self):
        plugins = {"litespeed-cache": {"found": True, "version": "6.4"}}
        with patch.object(cve_2024_28000, "run_aggressive_probe") as probe:
            result = cve_2024_28000.check(
                "https://target.test",
                run_exploit_check=True,
                exploit_mode="aggressive",
                plugins=plugins,
            )
        self.assertEqual(result.status, "PATCHED")
        self.assertFalse(result.exploit_ran)
        probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
