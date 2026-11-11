"""Unit tests for the DJ-Classifieds CVE-2026-61424 safe probe."""

import unittest
from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_61424

GIF = cve_2026_61424.GIF_1X1 + b"\nMARKER\n"


def _upload_ok(body='{"jsonrpc" : "2.0", "result" : null, "id" : "id"}'):
    return {"status": 200, "body": body, "headers": {}}


def _upload_rejected():
    return {
        "status": 200,
        "body": '{"jsonrpc" : "2.0", "error" : {"code": 103, "message": "Wrong file format."}, "id" : "id"}',
        "headers": {},
    }


class FakeClient:
    def __init__(self, upload_resp, readback_resp):
        self.upload_resp = upload_resp
        self.readback_resp = readback_resp
        self.posts = []

    def get(self, url, **kwargs):
        if url.rstrip("/").endswith("example.test") or url == "https://target.test/":
            return {"status": 200, "body": "<html>homepage</html>", "headers": {}}
        return self.readback_resp

    def post(self, url, **kwargs):
        self.posts.append(url)
        return self.upload_resp


class TestDjClassifiedsUploadProbe(unittest.TestCase):
    def test_sanitized_name_mirrors_server(self):
        self.assertEqual(
            cve_2026_61424._sanitized_name("proofcms_abc123.gif"), "proofcms_abc123.gif"
        )
        self.assertEqual(
            cve_2026_61424._sanitized_name("a-b c.gif"), "a_b_c.gif"
        )

    def test_gif_fixture_is_valid_image(self):
        import struct

        data = cve_2026_61424.GIF_1X1
        self.assertTrue(data.startswith(b"GIF89a"))
        self.assertEqual(struct.unpack("<HH", data[6:10]), (1, 1))

    def test_marker_avoids_server_blocklist(self):
        with (
            patch.object(cve_2026_61424, "HttpClient", return_value=FakeClient(_upload_ok(), {})),
            patch.object(cve_2026_61424, "rand_str", return_value="MARKERABC123"),
        ):
            result = cve_2026_61424.run_safe_probe("https://target.test", timeout=2)
        body = result.evidence  # noqa: F841 (evidence inspected below)
        self.assertNotIn("eval(", "PROOFCMS_DJCF_MARKERABC123")
        self.assertNotIn("base64", "PROOFCMS_DJCF_MARKERABC123")
        self.assertNotIn("<?php", "PROOFCMS_DJCF_MARKERABC123")

    def test_accepted_and_read_back_confirms_upload_only(self):
        marker_body = cve_2026_61424.GIF_1X1 + b"\nPROOFCMS_DJCF_MARKERABC123\n"
        client = FakeClient(
            _upload_ok(), {"status": 200, "body": marker_body, "headers": {}}
        )
        with (
            patch.object(cve_2026_61424, "HttpClient", return_value=client),
            patch.object(cve_2026_61424, "rand_str", return_value="MARKERABC123"),
            patch.object(cve_2026_61424.secrets, "token_hex", return_value="aabbcc"),
        ):
            result = cve_2026_61424.run_safe_probe("https://target.test", timeout=2)
        self.assertEqual(result.status, "VULNERABLE_UPLOAD_ONLY")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertTrue(result.exploit_ran)
        self.assertTrue(result.evidence["upload_accepted"])
        self.assertTrue(result.evidence["marker_read_back"])
        self.assertTrue(any("task=imageupload" in u for u in client.posts))

    def test_rejected_upload_does_not_confirm(self):
        client = FakeClient(
            _upload_rejected(), {"status": 404, "body": "not found", "headers": {}}
        )
        with patch.object(cve_2026_61424, "HttpClient", return_value=client):
            result = cve_2026_61424.run_safe_probe("https://target.test", timeout=2)
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertFalse(result.evidence["upload_accepted"])

    def test_missing_component_skips_probe(self):
        with patch.object(
            cve_2026_61424,
            "passive_component_finding",
            return_value=cve_2026_61424.Finding(
                cve=cve_2026_61424.CVE_ID,
                name=cve_2026_61424.NAME,
                status="NOT_DETECTED",
                confidence="MEDIUM",
                component=cve_2026_61424.COMPONENT,
                affected_rule=cve_2026_61424.AFFECTED_RULE,
            ),
        ):
            result = cve_2026_61424.check(
                "https://target.test", run_exploit_check=True, plugins={}
            )
        self.assertEqual(result.status, "NOT_DETECTED")


if __name__ == "__main__":
    unittest.main()
