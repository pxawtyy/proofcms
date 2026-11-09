"""Unit tests for the shared framework: auth, crawl, args, transcripts, cleanup."""

from __future__ import annotations

import argparse
import unittest
from typing import Any
from unittest.mock import patch

from proofcms.core import args as args_mod
from proofcms.core import auth as auth_mod
from proofcms.core import crawl as crawl_mod
from proofcms.core import transcript as transcript_mod
from proofcms.core.cleanup import cleanup_result
from proofcms.modules.wordpress import cve_2020_25213, cve_2026_18781


class FakeClient:
    """Minimal scripted stand-in for HttpSession/HttpClient."""

    def __init__(self, pages: dict[str, dict[str, Any]], base_url: str = "http://lab.test"):
        self.pages = pages
        self.base_url = base_url
        self.transcript: list[dict[str, Any]] = []

    def get(self, url: str, timeout: int | None = None) -> dict[str, Any]:
        return self._respond("GET", url)

    def post(self, url: str, fields: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        return self._respond("POST", url)

    def post_multipart(self, url: str, fields: dict[str, Any], files: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        return self._respond("POST", url)

    def _respond(self, method: str, url: str) -> dict[str, Any]:
        template = self.pages.get(url, {"status": 404, "body": "", "final_url": url, "redirected": False})
        resp = {**template} if isinstance(template, dict) else {"status": 404, "body": "", "final_url": url}
        resp.setdefault("final_url", url)
        self.transcript.append(transcript_mod.make_entry(method, url, resp))
        return resp


JOOMLA_LOGIN_PAGE = '<input type="hidden" name="abc123def456abc123def456abc12345" value="1" />'
WP_DASH = "Dashboard"


class TestSharedAuth(unittest.TestCase):
    def test_joomla_login_success(self):
        client = FakeClient(
            {
                "/administrator/index.php": {"status": 200, "body": JOOMLA_LOGIN_PAGE},
            }
        )

        def post(url: str, fields: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
            self.assertIn("abc123def456abc123def456abc12345", fields or {})
            self.assertEqual((fields or {}).get("passwd"), "secret")
            return {"status": 200, "body": "<div id=\"com_cpanel\">x</div>", "final_url": url}

        client.post = post  # type: ignore[method-assign]
        self.assertTrue(auth_mod.joomla_admin_login(client, "http://lab.test", "admin", "secret"))

    def test_joomla_login_no_token(self):
        client = FakeClient({"/administrator/index.php": {"status": 200, "body": "<form>no token</form>"}})
        self.assertFalse(auth_mod.joomla_admin_login(client, "http://lab.test", "admin", "secret"))

    def test_joomla_login_wrong_password(self):
        client = FakeClient({"/administrator/index.php": {"status": 200, "body": JOOMLA_LOGIN_PAGE}})

        def post(url: str, fields: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
            return {"status": 200, "body": "Username and password do not match", "final_url": url}

        client.post = post  # type: ignore[method-assign]
        self.assertFalse(auth_mod.joomla_admin_login(client, "http://lab.test", "admin", "wrong"))

    def test_verify_shape(self):
        client_pages = {"/administrator/index.php": {"status": 200, "body": JOOMLA_LOGIN_PAGE}}
        with patch.object(auth_mod, "HttpClient", return_value=FakeClient(client_pages)):
            result = auth_mod.verify_joomla_admin_login("http://lab.test", username="a", password="b")
        self.assertIn("logged_in", result)
        self.assertIn("status", result)

    def test_wordpress_login(self):
        client = FakeClient({"/wp-login.php": {"status": 200, "body": "login"}})

        def post(url: str, fields: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
            self.assertEqual((fields or {}).get("log"), "admin")
            return {"status": 200, "body": WP_DASH, "final_url": "http://lab.test/wp-admin/"}

        client.post = post  # type: ignore[method-assign]
        ok, final = auth_mod.wordpress_admin_login(client, "http://lab.test", "admin", "secret")
        self.assertTrue(ok)
        self.assertIn("wp-admin", final)


class TestSharedCrawl(unittest.TestCase):
    def test_extract_links_same_site_only(self):
        body = (
            '<a href="/about">a</a><a href="http://lab.test/contact">b</a>'
            '<a href="https://evil.test/x">c</a><a href="/img.png">d</a>'
            '<a href="mailto:a@b.c">e</a><a href="/about#frag">f</a>'
        )
        links = crawl_mod.extract_links(
            body, "http://lab.test/", skip_markers=crawl_mod.DEFAULT_SKIP_MARKERS
        )
        self.assertEqual(links, ["http://lab.test/about", "http://lab.test/contact"])

    def test_crawl_pages_caps_and_common_paths(self):
        def fetch(url: str) -> dict[str, Any]:
            if url == "http://lab.test/":
                return {"status": 200, "body": "".join(f'<a href="/p{i}">x</a>' for i in range(30))}
            return {"status": 404, "body": ""}

        pages = crawl_mod.crawl_pages(fetch, "http://lab.test", common_paths=("/", "/contact/"), max_pages=5)
        self.assertEqual(pages[0], "http://lab.test/")
        self.assertEqual(pages[1], "http://lab.test/contact/")
        self.assertEqual(len(pages), 5)

    def test_crawl_pages_homepage_down(self):
        pages = crawl_mod.crawl_pages(lambda url: {"status": 500, "body": ""}, "http://lab.test")
        self.assertEqual(pages, ["http://lab.test/"])

    def test_rest_list_links(self):
        def fetch(url: str) -> dict[str, Any]:
            if "rest_route" in url:
                return {"status": 200, "body": '[{"link": "http://lab.test/a"}, {"nope": 1}]'}
            return {"status": 404, "body": ""}

        self.assertEqual(
            crawl_mod.rest_list_links(fetch, "http://lab.test"),
            ["http://lab.test/", "http://lab.test/a"],
        )

    def test_rest_list_malformed(self):
        self.assertEqual(
            crawl_mod.rest_list_links(lambda url: {"status": 200, "body": "not-json"}, "http://lab.test"),
            ["http://lab.test/"],
        )


class TestAggressiveArgs(unittest.TestCase):
    def test_parse_round_trip(self):
        parsed = args_mod.parse_aggressive_args(["admin_user=admin", " cache_group = ../../x "])
        self.assertEqual(parsed, {"admin_user": "admin", "cache_group": "../../x"})

    def test_parse_value_with_equals(self):
        self.assertEqual(args_mod.parse_aggressive_args(["a=b=c"]), {"a": "b=c"})

    def test_parse_rejects(self):
        with self.assertRaises(ValueError):
            args_mod.parse_aggressive_args(["novalue"])
        with self.assertRaises(ValueError):
            args_mod.parse_aggressive_args(["=x"])
        with self.assertRaises(ValueError):
            args_mod.parse_aggressive_args(["a=1", "a=2"])

    def test_value_lookup(self):
        self.assertEqual(args_mod.aggressive_value({"k": "v"}, "old", "k"), "v")
        self.assertIsNone(args_mod.aggressive_value({}, "old", "k"))
        self.assertEqual(args_mod.aggressive_value({}, "old", "command"), "old")
        self.assertEqual(args_mod.aggressive_value(None, None, "command"), None)


class TestTranscript(unittest.TestCase):
    def test_entry_scrubs_userinfo(self):
        entry = transcript_mod.make_entry("GET", "http://user:pass@lab.test/x", {"status": 200, "body": "hi"})
        self.assertNotIn("user", entry["url"])
        self.assertEqual(entry["status"], 200)
        self.assertEqual(len(entry["body_hash"]), 16)

    def test_ring_take_clears(self):
        transcript_mod.take_transcript()  # drain entries left by other tests
        transcript_mod.record_stateless("GET", "http://lab.test/a", {"status": 200, "body": "x"})
        transcript_mod.record_stateless("POST", "http://lab.test/b", {"status": 500, "body": "y"})
        taken = transcript_mod.take_transcript()
        self.assertEqual([e["url"] for e in taken], ["http://lab.test/a", "http://lab.test/b"])
        self.assertEqual(transcript_mod.take_transcript(), [])

    def test_attach_from_client_limits(self):
        client = FakeClient({})
        client.transcript = [
            transcript_mod.make_entry("GET", f"http://lab.test/{i}", {"status": 200, "body": ""}) for i in range(20)
        ]
        out = transcript_mod.attach_transcript({"marker": True}, client, limit=5)
        self.assertEqual(len(out["transcript"]), 5)
        self.assertTrue(out["marker"])


class TestCleanupResult(unittest.TestCase):
    def test_ok_when_nothing_left(self):
        result = cleanup_result(removed=["a"])
        self.assertTrue(result["ok"])
        self.assertEqual(result["removed"], ["a"])

    def test_not_ok_with_remaining_or_manual(self):
        self.assertFalse(cleanup_result(remaining=["a"])["ok"])
        self.assertFalse(cleanup_result(manual=["do x"])["ok"])


class TestModuleCleanupHooks(unittest.TestCase):
    def test_25213_hash_direct(self):
        sess = FakeClient({})
        with (
            patch.object(cve_2020_25213, "HttpSession", return_value=sess),
            patch.object(cve_2020_25213, "_cleanup", return_value=True) as cleaner,
        ):
            result = cve_2020_25213.cleanup("http://lab.test", aggressive_args={"file_hash": "abc"})
        cleaner.assert_called_once()
        self.assertTrue(result["ok"])
        self.assertEqual(result["removed"], [f"{cve_2020_25213.CONNECTOR_PATH}#abc"])

    def test_25213_sweep(self):
        pages = {
            cve_2020_25213.CONNECTOR_PATH: {
                "status": 200,
                "body": '{"files": [{"name": "proofcms-a.php", "hash": "h1"}, {"name": "keep.php", "hash": "h2"}]}',
            }
        }
        sess = FakeClient(pages)
        with (
            patch.object(cve_2020_25213, "HttpSession", return_value=sess),
            patch.object(cve_2020_25213, "_cleanup", side_effect=lambda s, item, t: item["hash"] == "h1"),
        ):
            result = cve_2020_25213.cleanup("http://lab.test")
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["removed"]), 1)

    def test_18781_needs_args(self):
        result = cve_2026_18781.cleanup("http://lab.test", aggressive_args={})
        self.assertFalse(result["ok"])
        self.assertTrue(result["manual"])


class TestLabCleanupCLI(unittest.TestCase):
    def _args(self, **overrides: Any) -> argparse.Namespace:
        base = {
            "lab_cleanup": "CVE-2020-25213",
            "i_understand_authorized": True,
            "i_understand_lab_only": True,
            "timeout": 12,
            "proxy": None,
            "aggressive_command": None,
        }
        base.update(overrides)
        return argparse.Namespace(**base)

    def test_unknown_cve_rejected(self):
        from proofcms import cli as cli_mod

        self.assertEqual(cli_mod.run_lab_cleanup(self._args(lab_cleanup="CVE-0000-0000"), ["http://lab.test"], {}), 2)

    def test_no_hook_rejected(self):
        from proofcms import cli as cli_mod

        self.assertEqual(cli_mod.run_lab_cleanup(self._args(lab_cleanup="CVE-2026-90915"), ["http://lab.test"], {}), 2)

    def test_gates_authorization(self):
        from proofcms import cli as cli_mod

        self.assertEqual(
            cli_mod.run_lab_cleanup(self._args(i_understand_lab_only=False), ["http://lab.test"], {}), 2
        )


if __name__ == "__main__":
    unittest.main()
