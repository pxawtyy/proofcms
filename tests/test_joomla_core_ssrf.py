"""Unit tests for the Joomla core SSRF CVE-2026-92222 guest-side probe."""
import unittest
from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_92222


def _resp(status=200, body=""):
    return {"status": status, "body": body, "headers": {}, "redirected": False}


class FakeClient:
    def __init__(self, pages):
        self.pages = pages
        self.visited = []

    def get(self, url, **kwargs):
        self.visited.append(url)
        return self.pages.get(url.rstrip("/"), _resp(status=404, body="not found"))


def _feed_page(link, items=True):
    items_html = (
        '<h3 class="feed-link">PROOFCMS_SSRF_FILE01</h3>' if items else "<p>empty</p>"
    )
    error_html = "" if items else "<p>Feed could not be retrieved.</p>"
    return (
        f'<html><body><a href="{link}">{link}</a>'
        + items_html
        + error_html
        + "</body></html>"
    )


class TestNewsfeedsSsrfProbe(unittest.TestCase):
    def test_file_link_with_rendered_items_confirms(self):
        base = "https://target.test"
        cat = base + "/index.php?option=com_newsfeeds"
        feed = base + "/index.php/component/newsfeeds/newsfeed/proof?catid=5"
        pages = {
            base: _resp(body="<html>home</html>"),
            cat: _resp(
                body='<html><a href="/index.php/component/newsfeeds/newsfeed/proof?catid=5">f</a></html>'
            ),
            feed: _resp(body=_feed_page("file:///tmp/ssrf-feed.xml")),
        }
        with patch.object(cve_2026_92222, "HttpClient", return_value=FakeClient(pages)):
            result = cve_2026_92222.run_safe_probe(base, timeout=2)
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertTrue(result.exploit_ran)
        self.assertTrue(result.evidence["marker_found"])

    def test_http_only_feeds_do_not_confirm(self):
        base = "https://target.test"
        cat = base + "/index.php?option=com_newsfeeds"
        feed = base + "/index.php/component/newsfeeds/newsfeed/ok?catid=5"
        pages = {
            base: _resp(body="<html>home</html>"),
            cat: _resp(
                body='<html><a href="/index.php/component/newsfeeds/newsfeed/ok?catid=5">f</a></html>'
            ),
            feed: _resp(body=_feed_page("http://example.test/rss.xml")),
        }
        with patch.object(cve_2026_92222, "HttpClient", return_value=FakeClient(pages)):
            result = cve_2026_92222.run_safe_probe(base, timeout=2)
        self.assertEqual(result.status, "NOT_CONFIRMED")

    def test_unsafe_link_without_items_reports_exposure_only(self):
        base = "https://target.test"
        cat = base + "/index.php?option=com_newsfeeds"
        feed = base + "/index.php/component/newsfeeds/newsfeed/g?catid=5"
        pages = {
            base: _resp(body="<html>home</html>"),
            cat: _resp(
                body='<html><a href="/index.php/component/newsfeeds/newsfeed/g?catid=5">f</a></html>'
            ),
            feed: _resp(body=_feed_page("gopher://internal:7070/x", items=False)),
        }
        with patch.object(cve_2026_92222, "HttpClient", return_value=FakeClient(pages)):
            result = cve_2026_92222.run_safe_probe(base, timeout=2)
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertIn("gopher", result.evidence["unsafe_links"][0])

    def test_pathed_versions_stay_passive_without_probe(self):
        result = cve_2026_92222.check("https://target.test", joomla_version="5.4.8")
        self.assertEqual(result.status, "NOT_CONFIRMED")
        patched = cve_2026_92222.check("https://target.test", joomla_version="5.4.9")
        self.assertEqual(patched.status, "PATCHED")


if __name__ == "__main__":
    unittest.main()
