"""Unit tests for the Gridbox cookie authentication bypass CVE-2026-61425 probe."""
import unittest
from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_61425


class FakeClient:
    def __init__(self, state, fail=False):
        self.state = state
        self.fail = fail

    def get(self, url, **kwargs):
        if self.fail:
            return {"status": 0, "body": "", "error": "connection refused"}
        headers = kwargs.get("headers") or {}
        if cve_2026_61425.COOKIE_NAME in str(headers.get("Cookie", "")):
            self.state["forged"] = True
        if "com_config" in url:
            return {"status": 200 if self.state.get("forged") else 403, "body": "<html></html>", "headers": {}}
        if "com_users" in url and "profile" in url:
            user = self.state.get("user") if self.state["forged"] else None
            body = f'<input name="jform[username]" value="{user}">' if user else "<html></html>"
            return {"status": 200, "body": body, "headers": {}}
        return {"status": 200, "body": "<html>home</html>", "headers": {}}


def _run(state, **kwargs):
    def factory(*args, **kw):
        return FakeClient(state)
    with patch.object(cve_2026_61425, "HttpClient", side_effect=factory):
        return cve_2026_61425.run_aggressive_probe("https://target.test", timeout=2, **kwargs)


class TestGridboxCookieBypass(unittest.TestCase):
    def test_cookie_session_as_admin_confirms(self):
        state = {"user": "admin"}
        result = _run(state, admin_user="admin")
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertEqual(result.evidence["authenticated_identity"], "admin")
        self.assertEqual(result.evidence["guest_admin_status"], 403)
        self.assertEqual(result.evidence["forged_admin_status"], 200)

    def test_no_identity_does_not_confirm(self):
        state = {"user": None}
        result = _run(state, admin_user="admin")
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertIsNone(result.evidence["authenticated_identity"])

    def test_wrong_identity_does_not_confirm(self):
        state = {"user": "someoneelse"}
        result = _run(state, admin_user="admin")
        self.assertEqual(result.status, "NOT_CONFIRMED")

    def test_transport_error_reports_error(self):
        with patch.object(cve_2026_61425, "HttpClient", return_value=FakeClient({}, fail=True)):
            result = cve_2026_61425.run_aggressive_probe("https://target.test", timeout=2, admin_user="admin")
        self.assertEqual(result.status, "ERROR")

    def test_version_gates(self):
        self.assertEqual(cve_2026_61425.classify_version("2.20.0.2"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_61425.classify_version("1.6.0"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_61425.classify_version("2.20.1"), "PATCHED")
        self.assertEqual(cve_2026_61425.classify_version("2.20.5.0"), "PATCHED")
        self.assertEqual(cve_2026_61425.classify_version(None), "INCONCLUSIVE")

    def test_passive_not_detected(self):
        result = cve_2026_61425.passive_result({})
        self.assertEqual(result.status, "NOT_DETECTED")

    def test_check_gates_on_version_and_mode(self):
        state = {"user": "admin"}
        with patch.object(cve_2026_61425, "HttpClient", side_effect=lambda *a, **k: FakeClient(state)):
            safe = cve_2026_61425.check(
                "https://target.test", run_exploit_check=True, exploit_mode="safe",
                plugins={"gridbox": {"found": True, "version": "2.20.0.2"}},
            )
            self.assertEqual(safe.status, "LIKELY_VULNERABLE")
            patched = cve_2026_61425.check(
                "https://target.test", run_exploit_check=True, exploit_mode="aggressive",
                aggressive_args={"admin_user": "admin"},
                plugins={"gridbox": {"found": True, "version": "2.20.5.0"}},
            )
            self.assertEqual(patched.status, "PATCHED")


if __name__ == "__main__":
    unittest.main()
