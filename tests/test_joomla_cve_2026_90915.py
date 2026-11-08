import unittest
from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_90915

LOGIN_PAGE = '<input type="hidden" name="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" value="1">'
CACHE_PAGE = '<input type="hidden" name="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" value="1">'
CANARY = "http://target.test/cache-proofcms/marker.txt"


class FakeSession:
    def __init__(self, *, vulnerable=True, login_ok=True, canary_ok=True):
        self.vulnerable = vulnerable
        self.login_ok = login_ok
        self.canary_ok = canary_ok
        self.deleted = False
        self.posts = []

    def get(self, url, headers=None, timeout=None):
        if "cache-proofcms" in url:
            if not self.canary_ok:
                return {"status": 404, "body": ""}
            return {"status": 404 if self.deleted else 200, "body": "marker"}
        if "option=com_cache" in url:
            return {"status": 200, "body": CACHE_PAGE}
        return {"status": 200, "body": LOGIN_PAGE}

    def post(self, url, data=None, fields=None, files=None, headers=None, timeout=None):
        self.posts.append(dict(fields or {}))
        task = (fields or {}).get("task")
        if task == "login":
            return {"status": 200, "body": "com_cpanel" if self.login_ok else "login form"}
        if task == "display.delete":
            if self.vulnerable:
                self.deleted = True
            return {"status": 200, "body": "cleared"}
        return {"status": 200, "body": ""}


class TestCachePurgeVersionPolicy(unittest.TestCase):
    def test_version_boundary(self):
        self.assertEqual(cve_2026_90915.classify_version("3.10.12"), "NOT_AFFECTED")
        self.assertEqual(cve_2026_90915.classify_version("5.4.8"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_90915.classify_version("5.4.9"), "PATCHED")
        self.assertEqual(cve_2026_90915.classify_version("6.1.3"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_90915.classify_version("6.1.4"), "PATCHED")
        self.assertEqual(cve_2026_90915.classify_version(None), "INCONCLUSIVE")


class TestCachePurgeHelpers(unittest.TestCase):
    def test_parse_command(self):
        self.assertEqual(
            cve_2026_90915.parse_command("admin:secret|http://t/canary/m.txt|../../cache-proofcms"),
            ("admin", "secret", "http://t/canary/m.txt", "../../cache-proofcms"),
        )
        self.assertIsNone(cve_2026_90915.parse_command("admin:secret|http://t/canary/m.txt"))
        self.assertIsNone(cve_2026_90915.parse_command("admin|http://t/canary/m.txt|../../cache-proofcms"))
        self.assertIsNone(cve_2026_90915.parse_command(None))

    def test_csrf_extraction(self):
        self.assertEqual(
            cve_2026_90915._csrf(LOGIN_PAGE),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        self.assertIsNone(cve_2026_90915._csrf("<html></html>"))


class TestCachePurgeProbe(unittest.TestCase):
    def _run(self, fake):
        with patch.object(cve_2026_90915, "HttpSession", return_value=fake):
            return cve_2026_90915.run_aggressive_probe(
                "http://target.test",
                username="admin",
                password="secret",
                canary_url=CANARY,
                group="../../cache-proofcms",
            )

    def test_canary_deletion_is_confirmed(self):
        fake = FakeSession()
        result = self._run(fake)
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertTrue(result.exploit_ran)
        self.assertEqual(result.evidence["before_status"], 200)
        self.assertEqual(result.evidence["after_status"], 404)
        self.assertEqual(result.evidence["delete_status"], 200)
        self.assertEqual(result.proof_url, CANARY)
        self.assertEqual(fake.posts[1]["cid[]"], "../../cache-proofcms")

    def test_patched_target_is_not_confirmed(self):
        result = self._run(FakeSession(vulnerable=False))
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertEqual(result.evidence["after_status"], 200)

    def test_unreachable_canary_is_not_confirmed(self):
        result = self._run(FakeSession(canary_ok=False))
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertIn("canary URL", result.detail)

    def test_login_failure_is_not_confirmed(self):
        result = self._run(FakeSession(login_ok=False))
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertIn("credentials", result.detail)


class TestCachePurgeCheckGate(unittest.TestCase):
    def test_patched_version_skips_probe(self):
        with patch.object(cve_2026_90915, "run_aggressive_probe") as probe:
            result = cve_2026_90915.check(
                "https://target.test",
                joomla_version="5.4.9",
                run_exploit_check=True,
                exploit_mode="aggressive",
                aggressive_command="admin:secret|http://t/canary|../../cache-proofcms",
            )
        self.assertEqual(result.status, "PATCHED")
        probe.assert_not_called()

    def test_missing_command_does_not_delete(self):
        with patch.object(cve_2026_90915, "run_aggressive_probe") as probe:
            result = cve_2026_90915.check(
                "https://target.test",
                joomla_version="5.4.8",
                run_exploit_check=True,
                exploit_mode="aggressive",
            )
        probe.assert_not_called()
        self.assertIn("--aggressive-command", result.detail)

    def test_vulnerable_version_runs_probe(self):
        with patch.object(cve_2026_90915, "run_aggressive_probe") as probe:
            probe.return_value.status = "VULNERABLE"
            result = cve_2026_90915.check(
                "https://target.test",
                joomla_version="5.4.8",
                run_exploit_check=True,
                exploit_mode="aggressive",
                aggressive_command="admin:secret|http://t/canary|../../cache-proofcms",
            )
        probe.assert_called_once()
        self.assertEqual(result.status, "VULNERABLE")


if __name__ == "__main__":
    unittest.main()
