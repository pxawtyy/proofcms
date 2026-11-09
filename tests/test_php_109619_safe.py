"""Safe-probe tests for CVE-2026-109619 (stale-PSID leak unit)."""

import unittest
from unittest.mock import patch

from proofcms.modules.php import cve_2026_109619


def _responses(calls, script):
    def fake(url, data=None, headers=None, timeout=None):
        calls.append(url)
        for pattern, resp in script:
            if (pattern == "GET" and data is None) or (pattern == "POST" and data is not None):
                return dict(resp)
        return {"status": 404, "body": "", "headers": {}}

    return fake


class FakeSess:
    base_url = "http://lab.test"

    def __init__(self, script):
        self.script = script
        self.calls = []
        self.transcript = []

    def get(self, url, timeout=None):
        self.calls.append(("GET", url))
        return dict(self.script["GET"].pop(0))

    def post(self, url, data=None, headers=None, timeout=None):
        self.calls.append(("POST", url, len(data or b"")))
        return dict(self.script["POST"].pop(0))


class TestSafeLeakProbe(unittest.TestCase):
    def _run(self, get_responses, post_responses):
        sess = FakeSess({"GET": list(get_responses), "POST": list(post_responses)})
        with patch.object(cve_2026_109619, "HttpSession", return_value=sess):
            return cve_2026_109619.run_safe_probe("http://lab.test"), sess

    def test_leak_confirms(self):
        big_cookie = "L" + "A" * 4095
        result, _ = self._run(
            [{"status": 200, "body": "OK\n", "headers": {}}],
            [
                {"status": 200, "body": "Warning: input vars", "headers": {}},
                {
                    "status": 200,
                    "body": "Warning: Failed to create session data file",
                    "headers": {"set-cookie": [f"PHPSESSID={big_cookie}; path=/"]},
                },
            ],
        )
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertGreater(result.evidence["cookie_len"], 1000)

    def test_fresh_cookie_does_not_confirm(self):
        result, _ = self._run(
            [{"status": 200, "body": "OK\n", "headers": {}}],
            [
                {"status": 200, "body": "Warning: input vars", "headers": {}},
                {
                    "status": 200,
                    "body": "SID=abc\nOK\n",
                    "headers": {"set-cookie": ["PHPSESSID=abc123; path=/"]},
                },
            ],
        )
        self.assertEqual(result.status, "NOT_CONFIRMED")

    def test_missing_baseline_skips_payload(self):
        sess = FakeSess(
            {
                "GET": [{"status": 404, "body": "missing", "headers": {}}],
                "POST": [{"status": 200, "body": "x", "headers": {}}],
            }
        )
        with patch.object(cve_2026_109619, "HttpSession", return_value=sess):
            result = cve_2026_109619.run_safe_probe("http://lab.test")
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertEqual([c for c in sess.calls if c[0] == "POST"], [])

    def test_safe_mode_routes_to_safe_probe(self):
        from proofcms.core.models import Finding

        sentinel = Finding("CVE-2026-109619", "x", "NOT_CONFIRMED", "MEDIUM", "PHP runtime")
        with patch.object(cve_2026_109619, "run_safe_probe", return_value=sentinel) as probe:
            result = cve_2026_109619.check(
                "https://fixture.test",
                php_runtime={"detected": True, "version": "8.3.35", "source": "X-Powered-By"},
                run_exploit_check=True,
                exploit_mode="safe",
            )
        probe.assert_called_once()
        self.assertIs(result, sentinel)


if __name__ == "__main__":
    unittest.main()
