import re
import unittest
from unittest.mock import patch

from proofcms.modules.joomla import cve_2017_8917


class FakeSession:
    def __init__(self, *, vulnerable=True, marker_works=True):
        self.vulnerable = vulnerable
        self.marker_works = marker_works
        self.requests = []

    def request(self, url, method="GET", timeout=None, follow_redirects=True):
        self.requests.append(url)
        if not self.vulnerable:
            return {"status": 303, "body": ""}
        if "extractvalue" in url and self.marker_works:
            hex_values = re.findall(r"0x([0-9a-f]+)", url)
            marker = bytes.fromhex(max(hex_values, key=len)).decode() if hex_values else "unknown"
            return {"status": 500, "body": f"XPATH syntax error: '~{marker}~'"}
        return {"status": 303, "body": ""}


class TestJoomlaSqlInjectionVersionPolicy(unittest.TestCase):
    def test_version_boundary(self):
        self.assertEqual(cve_2017_8917.classify_version("3.7.0"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2017_8917.classify_version("3.6.3"), "NOT_AFFECTED")
        self.assertEqual(cve_2017_8917.classify_version("3.7.1"), "PATCHED")
        self.assertEqual(cve_2017_8917.classify_version("3.8.11"), "PATCHED")
        self.assertEqual(cve_2017_8917.classify_version(None), "INCONCLUSIVE")


class TestJoomlaSqlInjectionHelpers(unittest.TestCase):
    def test_endpoint_encodes_fullordering_array(self):
        endpoint = cve_2017_8917._endpoint("com_content.article", "a.ordering")
        self.assertIn("option=com_fields", endpoint)
        self.assertIn("view=fields", endpoint)
        self.assertIn("layout=modal", endpoint)
        self.assertIn("list%5Bfullordering%5D=a.ordering", endpoint)

    def test_xpath_marker_extraction(self):
        body = "XPATH syntax error: &#039;~PROOFCMS_MARKER_ABC123~&#039;"
        self.assertEqual(cve_2017_8917._xpath_marker(body), "PROOFCMS_MARKER_ABC123")
        self.assertIsNone(cve_2017_8917._xpath_marker("normal page"))


class TestJoomlaSqlInjectionProbe(unittest.TestCase):
    def test_marker_reflection_is_confirmed(self):
        fake = FakeSession()
        with patch.object(cve_2017_8917, "HttpSession", return_value=fake):
            result = cve_2017_8917.run_aggressive_probe("https://target.test")
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertTrue(result.exploit_ran)
        self.assertEqual(result.evidence["baseline_status"], 303)
        self.assertEqual(result.evidence["payload_status"], 500)
        self.assertEqual(result.evidence["error_signature"], "XPATH syntax error")
        self.assertIn("extractvalue", fake.requests[1])

    def test_time_based_fallback_is_confirmed(self):
        def fake_timed_get(sess, path, timeout):
            if "SLEEP" in path:
                return {"status": 303, "body": ""}, 5.3
            return {"status": 303, "body": ""}, 0.2

        with (
            patch.object(cve_2017_8917, "HttpSession", return_value=FakeSession(marker_works=False)),
            patch.object(cve_2017_8917, "_timed_get", side_effect=fake_timed_get),
        ):
            result = cve_2017_8917.run_aggressive_probe("https://target.test")
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertIn("SLEEP", result.detail)
        self.assertEqual(result.evidence["sleep_time"], 5.3)

    def test_patched_target_is_not_confirmed(self):
        with patch.object(cve_2017_8917, "HttpSession", return_value=FakeSession(vulnerable=False)):
            result = cve_2017_8917.run_aggressive_probe("https://target.test")
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertTrue(result.exploit_ran)


class TestJoomlaSqlInjectionCheckGate(unittest.TestCase):
    def test_patched_version_skips_probe(self):
        with patch.object(cve_2017_8917, "run_aggressive_probe") as probe:
            result = cve_2017_8917.check(
                "https://target.test",
                joomla_version="3.8.11",
                run_exploit_check=True,
                exploit_mode="aggressive",
            )
        self.assertEqual(result.status, "PATCHED")
        self.assertFalse(result.exploit_ran)
        probe.assert_not_called()

    def test_vulnerable_version_runs_probe(self):
        with patch.object(cve_2017_8917, "run_aggressive_probe") as probe:
            probe.return_value.status = "VULNERABLE"
            result = cve_2017_8917.check(
                "https://target.test",
                joomla_version="3.7.0",
                run_exploit_check=True,
                exploit_mode="aggressive",
                aggressive_command="com_content.article",
            )
        probe.assert_called_once()
        self.assertEqual(result.status, "VULNERABLE")


if __name__ == "__main__":
    unittest.main()
