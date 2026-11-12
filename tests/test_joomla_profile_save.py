"""Unit tests for the Joomla guest profile.save CVE-2026-90907 probe."""
import unittest
from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_90907

TOKEN = "0123456789abcdef0123456789abcdef"


class FakeClient:
    def __init__(self, state):
        self.state = state

    def get(self, url, **kwargs):
        if url.rstrip("/").endswith("/index.php") or url.endswith("/"):
            body = f'{{"csrf.token":"{TOKEN}"}}' if self.state.get("token", True) else "<html></html>"
            return {"status": 200, "body": body, "headers": {}, "final_url": url}
        return {"status": 200, "body": "<html></html>", "headers": {}, "final_url": url}

    def request(self, url, **kwargs):
        if self.state.get("vulnerable", True):
            return {"status": 303, "body": "",
                    "headers": {"Location": "http://t/index.php/component/users/profile?user_id=42"},
                    "final_url": url}
        return {"status": 403, "body": "", "headers": {}, "final_url": url}


def _run(state):
    with patch.object(cve_2026_90907, "HttpClient", side_effect=lambda *a, **k: FakeClient(state)):
        return cve_2026_90907.run_aggressive_probe("https://target.test", timeout=2)


class TestGuestProfileSave(unittest.TestCase):
    def test_created_user_id_confirms(self):
        result = _run({"vulnerable": True})
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertEqual(result.evidence["redirect_user_id"], 42)

    def test_guest_403_does_not_confirm(self):
        result = _run({"vulnerable": False})
        self.assertEqual(result.status, "NOT_CONFIRMED")

    def test_missing_token_does_not_confirm(self):
        result = _run({"token": False})
        self.assertEqual(result.status, "NOT_CONFIRMED")

    def test_version_gates(self):
        self.assertEqual(cve_2026_90907.classify_version("5.4.8"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_90907.classify_version("5.4.9"), "PATCHED")
        self.assertEqual(cve_2026_90907.classify_version("6.1.3"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_90907.classify_version("6.1.4"), "PATCHED")
        self.assertEqual(cve_2026_90907.classify_version("1.5.0"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_90907.classify_version("1.0.0"), "NOT_AFFECTED")
        self.assertEqual(cve_2026_90907.classify_version(None), "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
