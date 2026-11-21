from __future__ import annotations

from unittest.mock import patch

from proofcms.detectors import wordpress


def _response(status: int = 404, body: str = "", url: str = "") -> dict:
    return {"status": status, "body": body, "final_url": url, "body_hash": str(status)}


def test_reported_plugin_slugs_have_markers():
    for slug in (
        "wp-libre-form",
        "elex-helpdesk-customer-support-ticket-system",
        "elementor-pro",
        "wp-photo-album-plus",
        "wp-compress-image-optimizer",
        "ai-workflow-automation-ai-agent-hub",
    ):
        assert slug in wordpress.KNOWN_PLUGIN_MARKERS


def test_required_inventory_only_probes_requested_markers():
    requested: list[str] = []

    def fetch(url: str, **kwargs):
        requested.append(url)
        if url.endswith("/"):
            return _response(200, "<html>WordPress</html>", url)
        if url.endswith("/wp-json/"):
            return _response(404, "", url)
        return _response(404, "", url)

    with (
        patch.object(wordpress, "_fetch", side_effect=fetch),
        patch.object(wordpress, "detect_wordpress_theme", return_value={"found": False}),
    ):
        result = wordpress.detect_wordpress_plugins(
            "https://fixture.test",
            1,
            required_plugins={"wp-libre-form"},
        )

    assert "wp-libre-form" in " ".join(requested)
    assert "wp-photo-album-plus" not in " ".join(requested)
    assert result["plugins"] == {}


def test_inventory_uses_configured_concurrency():
    class FakeExecutor:
        last_max_workers = None

        def __init__(self, max_workers=None):
            self.max_workers = max_workers
            FakeExecutor.last_max_workers = max_workers

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def map(self, fn, values):
            return [fn(value) for value in values]

    def fetch(url: str, **kwargs):
        if url.endswith("/"):
            return _response(200, "<html>WordPress</html>", url)
        return _response(404, "", url)

    with (
        patch.object(wordpress, "_fetch", side_effect=fetch),
        patch.object(wordpress, "detect_wordpress_theme", return_value={"found": False}),
        patch("concurrent.futures.ThreadPoolExecutor", FakeExecutor),
    ):
        wordpress.detect_wordpress_plugins(
            "https://fixture.test",
            1,
            concurrency=3,
            required_plugins={"wp-libre-form", "elementor-pro", "wp-photo-album-plus"},
        )

    assert FakeExecutor.last_max_workers == 3
