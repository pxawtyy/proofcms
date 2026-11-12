"""Active-probe tests for the Joomla com_fields API ACL CVE-2026-72531."""
import unittest
from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_72531

TOKEN = "lab-api-token"


class FakeClient:
    def __init__(self, state):
        self.state = state

    def get(self, url, **kwargs):
        return {"status": 200, "body": "<html></html>", "headers": {}, "final_url": url}

    def request(self, url, **kwargs):
        if self.state.get("vulnerable"):
            return {
                "status": 200,
                "body": '{"data":{"type":"fields","id":"12","attributes":{"name":"proofcms_field"}}}',
                "headers": {},
                "final_url": url,
            }
        return {
            "status": 403,
            "body": '{"errors":[{"title":"Forbidden"}]}',
            "headers": {},
            "final_url": url,
        }


def _run(state, token=TOKEN, mode="aggressive"):
    with patch.object(cve_2026_72531, "HttpClient", side_effect=lambda *a, **k: FakeClient(state)):
        return cve_2026_72531.check(
            "https://fixture.test",
            joomla_version="5.4.7",
            run_exploit_check=True,
            exploit_mode=mode,
            aggressive_args={"api_token": token} if token else None,
        )


class TestFieldsApiAcl(unittest.TestCase):
    def test_created_field_confirms(self):
        result = _run({"vulnerable": True})
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertEqual(result.evidence["created_field_id"], 12)
        self.assertTrue(result.evidence["field_name"].startswith("proofcms_field_"))

    def test_forbidden_does_not_confirm(self):
        result = _run({"vulnerable": False})
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertEqual(result.evidence["status"], 403)

    def test_missing_token_blocks(self):
        result = _run({"vulnerable": True}, token=None)
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")

    def test_safe_mode_keeps_passive_result(self):
        result = _run({"vulnerable": True}, mode="safe")
        self.assertEqual(result.status, "LIKELY_VULNERABLE")
        self.assertFalse(result.exploit_ran)

    def test_metadata_advertises_aggressive_mode(self):
        metadata = cve_2026_72531.metadata()
        self.assertEqual(metadata["exploit_modes"], ["aggressive"])
        self.assertTrue(metadata["intrusive"])


if __name__ == "__main__":
    unittest.main()
