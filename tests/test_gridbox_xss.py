"""Regression tests for the Gridbox stored-XSS CVEs (105607 / 107903)."""
import html
import json
import re
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

from proofcms.modules.joomla import cve_2026_105607, cve_2026_107903


def _fields(data):
    if isinstance(data, bytes):
        data = data.decode()
    return {k: v[-1] for k, v in parse_qs(data).items()}


class FakeClient:
    def __init__(self, state):
        self.state = state

    def get(self, url, **kwargs):
        s = self.state
        if "editor.getRecentComments" in url:
            payload = s.get("comment_payload", "")
            body = payload if s.get("xss") else html.escape(payload)
            return {"status": 200, "body": body, "headers": {}}
        if "editor.getRecentReviews" in url:
            payload = s.get("review_payload", "")
            body = payload if s.get("xss") else html.escape(payload)
            return {"status": 200, "body": f'<a href="http://t/index.php/reviewID-5">x</a>{body}', "headers": {}}
        if "reviews.getReviewById" in url:
            payload = s.get("review_payload", "")
            comment = payload if s.get("xss") else re.sub(r"<[^>]+>", "", payload)
            return {"status": 200, "body": json.dumps({"comment": comment, "commentMessage": ""}), "headers": {}}
        return {"status": 200, "body": "<html></html>", "headers": {}}

    def request(self, url, **kwargs):
        fields = _fields(kwargs.get("data") or b"")
        if "comments.sendCommentMesssage" in url:
            self.state["comment_payload"] = fields.get("message", "")
        if "reviews.sendCommentMesssage" in url:
            self.state["review_payload"] = fields.get("message", "")
        return {"status": 200, "body": '{"message":"ok"}', "headers": {}}


def _run(module, state, **kwargs):
    with patch.object(module, "HttpClient", side_effect=lambda *a, **k: FakeClient(state)):
        return module.run_aggressive_probe("https://target.test", timeout=2, **kwargs)


class TestGridboxStoredXss(unittest.TestCase):
    def test_105607_widgets_confirm_and_negative(self):
        self.assertEqual(_run(cve_2026_105607, {"xss": True}).status, "VULNERABLE")
        self.assertEqual(_run(cve_2026_105607, {"xss": False}).status, "NOT_CONFIRMED")

    def test_107903_get_review_by_id_confirms_and_negative(self):
        ok = _run(cve_2026_107903, {"xss": True})
        self.assertEqual(ok.status, "VULNERABLE")
        self.assertEqual(ok.evidence["review_id"], "5")
        self.assertEqual(_run(cve_2026_107903, {"xss": False}).status, "NOT_CONFIRMED")

    def test_version_gates(self):
        for module in (cve_2026_105607, cve_2026_107903):
            self.assertEqual(
                module.check("https://t.test", plugins={"gridbox": {"found": True, "version": "2.20.4.2"}}).status,
                "LIKELY_VULNERABLE",
            )
            self.assertEqual(
                module.check("https://t.test", plugins={"gridbox": {"found": True, "version": "2.20.5.0"}}).status,
                "PATCHED",
            )


if __name__ == "__main__":
    unittest.main()
