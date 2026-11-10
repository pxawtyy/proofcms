"""Unit tests for the iCagenda CVE-2026-48939 aggressive probe (4.x submit flow)."""
import re
import unittest
from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_48939


class TestIcagendaVersionGate(unittest.TestCase):
    def test_affected_branches_are_likely_vulnerable(self):
        for version in ("3.2.1", "3.7.21", "3.9.14", "4.0.0", "4.0.7"):
            plugins = {"icagenda": {"found": True, "version": version, "source": "manifest"}}
            result = cve_2026_48939.check("https://target.test", plugins=plugins)
            self.assertEqual(result.status, "LIKELY_VULNERABLE", version)

    def test_fixed_releases_are_patched(self):
        for version in ("3.9.15", "4.0.8", "4.1.0"):
            plugins = {"icagenda": {"found": True, "version": version, "source": "manifest"}}
            result = cve_2026_48939.check("https://target.test", plugins=plugins)
            self.assertEqual(result.status, "PATCHED", version)


class TestSubmitProfileFields(unittest.TestCase):
    def test_profile_carries_token_dated_jform_fields(self):
        fields = cve_2026_48939.submit_profile_fields("abc123", "112")
        self.assertEqual(fields["jform[title]"], "ProofCMS Lab Test")
        self.assertEqual(fields["jform[catid]"], "1")
        self.assertEqual(fields["jform[consent][consent_tos]"], "tos")
        self.assertEqual(fields["abc123"], "1")
        self.assertEqual(fields["jform[itemid]"], "112")
        self.assertRegex(fields["jform[startdate]"], r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")


class TestDiscoverSubmitContext(unittest.TestCase):
    def test_extracts_token_and_itemid(self):
        html = (
            '<form action="/index.php/submit-event" method="post">'
            '<input type="hidden" name="jform[itemid]" value="112">'
            '<input type="hidden" name="0123456789abcdef0123456789abcdef" value="1">'
            '</form>'
        )

        def fake_request(url, **kwargs):
            if "view=submit" in url or url.endswith("/submit-event"):
                return {"status": 200, "body": html}
            return {"status": 404, "body": ""}

        with patch.object(cve_2026_48939, "request", side_effect=fake_request):
            token, itemid = cve_2026_48939._discover_submit_context(
                "https://target.test", timeout=2, proxy=None
            )
        self.assertEqual(token, "0123456789abcdef0123456789abcdef")
        self.assertEqual(itemid, "112")


class TestAggressiveProbeSubmitFlow(unittest.TestCase):
    FORM_HTML = (
        '<form action="/index.php/submit-event" method="post">'
        '<input type="hidden" name="jform[itemid]" value="112">'
        '<input type="hidden" name="0123456789abcdef0123456789abcdef" value="1">'
        '<input type="file" name="jform[file]">'
        '</form>'
    )

    def _fake_request(self, state):
        def fake_request(url, **kwargs):
            method = kwargs.get("method", "GET")
            if method == "GET" and ("submit" in url or url.rstrip("/") == "https://target.test"):
                return {"status": 200, "body": self.FORM_HTML}
            if method == "POST" and "task=submit.submit" in url:
                status = state.get("upload_status", 200)
                body = kwargs.get("data", b"")
                raw = bytes(body) if isinstance(body, (bytes, bytearray)) else b""
                if status == 200:
                    match = re.search(rb"JVH_ICAGENDA_CONFIRMED_[A-Za-z0-9]+", raw)
                    if match:
                        state["marker"] = match.group(0).decode()
                        state["seen"] = True
                return {"status": status, "body": state.get("upload_body", '{"success": true}')}
            if method == "GET" and url.endswith(".php"):
                if state.get("seen") and state.get("marker") and state.get("readback", True):
                    return {"status": 200, "body": "executed {}_144".format(state["marker"])}
                return {"status": 404, "body": "not found"}
            return {"status": 404, "body": ""}
        return fake_request

    def test_submit_flow_confirms_execution(self):
        state = {}
        real_poll = cve_2026_48939.poll_paths

        def fast_poll(fetch, urls, deadline=3.0, initial_delay=0.1, accept_fn=None):
            return real_poll(fetch, urls, deadline=0.05, initial_delay=0, accept_fn=accept_fn)

        with (
            patch.object(cve_2026_48939, "request", side_effect=self._fake_request(state)),
            patch.object(cve_2026_48939, "poll_paths", side_effect=fast_poll),
        ):
            result = cve_2026_48939.run_aggressive_probe(
                "https://target.test", timeout=2, proxy=None
            )
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertTrue(result.proof_url.endswith(".php"))
        self.assertTrue(result.exploit_ran)

    def test_rejected_upload_is_not_confirmed(self):
        state = {"upload_status": 500, "upload_body": "error"}
        real_poll = cve_2026_48939.poll_paths

        def fast_poll(fetch, urls, deadline=3.0, initial_delay=0.1, accept_fn=None):
            return real_poll(fetch, urls, deadline=0.05, initial_delay=0, accept_fn=accept_fn)

        with (
            patch.object(cve_2026_48939, "request", side_effect=self._fake_request(state)),
            patch.object(cve_2026_48939, "poll_paths", side_effect=fast_poll),
        ):
            result = cve_2026_48939.run_aggressive_probe(
                "https://target.test", timeout=2, proxy=None
            )
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertTrue(result.exploit_ran)


if __name__ == "__main__":
    unittest.main()
