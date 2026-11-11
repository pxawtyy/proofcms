"""Unit tests for the WPvivid CVE-2026-1357 safe probe."""
import base64
import unittest
from unittest.mock import patch

from proofcms.modules.wordpress import cve_2026_1357


def _content(marker="M"):
    return base64.b64encode(b"000" + b"0123").decode()


class FakeClient:
    def __init__(self, upload_resp, readback_resp):
        self.upload_resp = upload_resp
        self.readback_resp = readback_resp
        self.posts = []

    def get(self, url, **kwargs):
        if url.rstrip("/") == "https://target.test":
            return {"status": 200, "body": "<html>home</html>", "headers": {}}
        return self.readback_resp

    def post(self, url, **kwargs):
        self.posts.append(url)
        return self.upload_resp


def _run(client):
    with (
        patch.object(cve_2026_1357, "HttpSession", return_value=client),
        patch.object(cve_2026_1357, "rand_str", return_value="MARKERABC"),
    ):
        return cve_2026_1357.run_safe_probe("https://target.test", timeout=2)


class TestWpvividNullKeyProbe(unittest.TestCase):
    def test_envelope_shape(self):
        content = cve_2026_1357._encrypted_content({"a": 1})
        raw = base64.b64decode(content)
        self.assertTrue(raw.startswith(b"000"))
        self.assertEqual(len(raw), 3 + 16 + 16)

    def test_accepted_and_read_back_confirms_upload_only(self):
        marker = "PROOFCMS_WPVIVID_MARKERABC"
        body = "x" * 10 + marker + "y" * 10
        client = FakeClient(
            {"status": 200, "body": '{"result":"success","op":"finished"}', "headers": {}},
            {"status": 200, "body": body, "headers": {}},
        )
        result = _run(client)
        self.assertEqual(result.status, "VULNERABLE_UPLOAD_ONLY")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertTrue(result.exploit_ran)
        self.assertTrue(result.evidence["marker_read_back"])
        self.assertTrue(client.posts)
        self.assertTrue(all(u == "https://target.test/" for u in client.posts))

    def test_rejected_upload_does_not_confirm(self):
        client = FakeClient(
            {"status": 200, "body": '{"result":"failed","error":"The key is invalid."}', "headers": {}},
            {"status": 404, "body": "not found", "headers": {}},
        )
        result = _run(client)
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertFalse(result.evidence["upload_accepted"])

    def test_missing_crypto_blocks_externally(self):
        import sys
        from unittest.mock import patch as _patch

        with (
            _patch.dict(sys.modules, {
                "cryptography.hazmat.primitives.ciphers": None,
                "cryptography.hazmat.primitives.padding": None,
            }),
            _patch.object(cve_2026_1357, "HttpSession", return_value=FakeClient({}, {})),
        ):
            result = cve_2026_1357.run_safe_probe("https://target.test", timeout=2)
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")


if __name__ == "__main__":
    unittest.main()
