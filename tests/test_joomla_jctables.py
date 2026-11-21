"""Unit tests for the JCTables CVE-2026-76570 safe boolean probe."""
import unittest
from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_76570


class FakeClient:
    def __init__(self, bodies):
        self.bodies = bodies
        self.calls = []

    def get(self, url, **kwargs):
        if url.rstrip("/").endswith("example.test") or url == "https://target.test/":
            return {"status": 200, "body": "<html>home</html>", "headers": {}}
        self.calls.append(url)
        idx = (len(self.calls) - 1) % len(self.bodies)
        return {"status": 200, "body": self.bodies[idx], "headers": {}}


class TestJcTablesVersionPolicy(unittest.TestCase):
    def test_affected_range(self):
        self.assertTrue(cve_2026_76570.affected_jctables("1.0.0"))
        self.assertTrue(cve_2026_76570.affected_jctables("1.20.0"))
        self.assertFalse(cve_2026_76570.affected_jctables("1.21.1"))
        self.assertFalse(cve_2026_76570.affected_jctables("1.21.2"))
        self.assertIsNone(cve_2026_76570.affected_jctables(None))
        self.assertIsNone(cve_2026_76570.affected_jctables("not-a-version"))

    def test_passive_states(self):
        vuln = cve_2026_76570.check(
            "https://target.test", plugins={"jctables": {"found": True, "version": "1.20.0"}}
        )
        self.assertEqual(vuln.status, "LIKELY_VULNERABLE")
        fixed = cve_2026_76570.check(
            "https://target.test", plugins={"jctables": {"found": True, "version": "1.21.1"}}
        )
        self.assertEqual(fixed.status, "NOT_AFFECTED")
        missing = cve_2026_76570.check("https://target.test", plugins={})
        self.assertEqual(missing.status, "NOT_DETECTED")


class TestJcTablesBooleanProbe(unittest.TestCase):
    def test_differential_confirms(self):
        true_body = '{"success":true,"data":{"data":[{"id":595}],"table_id":"0","row_id":"true"}}'
        false_body = '{"success":true,"data":{"data":[[]],"table_id":"0","row_id":"false"}}'
        client = FakeClient([true_body, false_body])
        with patch.object(cve_2026_76570, "HttpClient", return_value=client):
            result = cve_2026_76570.run_safe_probe("https://target.test", timeout=2)
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertTrue(result.exploit_ran)
        self.assertTrue(result.evidence["boolean_differential"])
        self.assertEqual(result.evidence["comparison"], "data.data")

    def test_request_keeps_component_and_json_format(self):
        client = FakeClient(['{"success":true,"data":{"data":[]}}'] * 2)
        with patch.object(cve_2026_76570, "HttpClient", return_value=client):
            cve_2026_76570.run_safe_probe("https://target.test", timeout=2)
        self.assertTrue(client.calls)
        for url in client.calls:
            self.assertIn("option=com_jctables", url)
            self.assertIn("format=json", url)
            self.assertIn("task=getrow", url)

    def test_identical_responses_do_not_confirm(self):
        body = '{"error": "no such table"}'
        client = FakeClient([body, body])
        with patch.object(cve_2026_76570, "HttpClient", return_value=client):
            result = cve_2026_76570.run_safe_probe("https://target.test", timeout=2)
        self.assertEqual(result.status, "NOT_CONFIRMED")

    def test_body_only_difference_does_not_confirm(self):
        true_body = '<html><link rel="canonical" href="?idx=%27%27+OR+%281%3D1%29+OR+%27%27"></html>'
        false_body = '<html><link rel="canonical" href="?idx=%27%27+OR+%281%3D2%29+OR+%27%27"></html>'
        client = FakeClient([true_body, false_body])
        with patch.object(cve_2026_76570, "HttpClient", return_value=client):
            result = cve_2026_76570.run_safe_probe("https://target.test", timeout=2)
        self.assertEqual(result.status, "NOT_CONFIRMED")

    def test_row_id_echo_alone_does_not_confirm(self):
        true_body = '{"success":true,"data":{"data":[[]],"table_id":"0","row_id":"true"}}'
        false_body = '{"success":true,"data":{"data":[[]],"table_id":"0","row_id":"false"}}'
        client = FakeClient([true_body, false_body])
        with patch.object(cve_2026_76570, "HttpClient", return_value=client):
            result = cve_2026_76570.run_safe_probe("https://target.test", timeout=2)
        self.assertEqual(result.status, "NOT_CONFIRMED")

    def test_aggressive_mode_refused(self):
        result = cve_2026_76570.check(
            "https://target.test", run_exploit_check=True, exploit_mode="aggressive",
            plugins={"jctables": {"found": True, "version": "1.20.0"}},
        )
        self.assertEqual(result.status, "LIKELY_VULNERABLE")
        self.assertIn("safe", result.detail)


if __name__ == "__main__":
    unittest.main()
