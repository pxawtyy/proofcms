"""Shared page discovery: REST listings plus same-site link crawling.

Four modules re-implemented the same two shapes: WordPress ``?rest_route=``
page listings (forminator advisory, CVE-2026-32475) and homepage ``href``
crawls with skip markers (EAEL, CF7 bypass, DND upload, Convert Forms).
Both live here now, parameterised by the bits that actually differ
(``per_page``, ``common_paths``, ``max_pages``, ``skip_markers``); the
HTML field parsers stay in their modules.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from collections.abc import Callable
from typing import Any

from .http import normalize_url

Response = dict[str, Any]
Fetch = Callable[[str], Response]

DEFAULT_SKIP_MARKERS = (
    "wp-admin",
    "wp-login",
    "wp-json",
    "xmlrpc",
    "feed",
    "mailto:",
    "javascript:",
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
)


def same_site(base_url: str, url: str) -> bool:
    """Return True when both URLs share a host (case-insensitive)."""
    return urllib.parse.urlsplit(base_url).netloc.lower() == urllib.parse.urlsplit(url).netloc.lower()


def extract_links(
    body: str,
    base_url: str,
    skip_markers: tuple[str, ...] = (),
) -> list[str]:
    """Return distinct same-site ``href`` targets in page order.

    ``mailto:``/``javascript:``/asset links are skipped via ``skip_markers``;
    fragments are dropped so ``/page#a`` and ``/page#b`` collapse to one.
    """
    found: list[str] = []
    for href in re.findall(r'href=["\']([^"\']+)["\']', body or "", re.IGNORECASE):
        lowered = href.lower()
        if any(marker in lowered for marker in skip_markers):
            continue
        url = urllib.parse.urljoin(base_url.rstrip("/") + "/", href)
        url, _ = urllib.parse.urldefrag(url)
        if not same_site(base_url, url) or url in found:
            continue
        found.append(url)
    return found


def crawl_pages(
    fetch: Fetch,
    base_url: str,
    *,
    common_paths: tuple[str, ...] = ("/",),
    max_pages: int = 12,
    skip_markers: tuple[str, ...] = DEFAULT_SKIP_MARKERS,
) -> list[str]:
    """Return seed paths plus same-site links crawled from the homepage.

    ``fetch`` maps a URL to a response dict (``status``/``body``). The crawl
    is read-only: only the homepage is fetched, links are never followed.
    """
    base = normalize_url(base_url)
    pages = [f"{base}{path}" for path in common_paths]
    homepage = fetch(f"{base}/")
    if homepage.get("status") == 200:
        for url in extract_links(str(homepage.get("body", "")), base, skip_markers):
            if url not in pages:
                pages.append(url)
            if len(pages) >= max_pages:
                break
    return pages


def rest_list_links(
    fetch: Fetch,
    base_url: str,
    *,
    route: str = "/wp/v2/pages",
    per_page: int = 50,
    fields: str = "link",
    link_key: str = "link",
) -> list[str]:
    """Return ``[home] + REST-listed`` WordPress URLs, deduplicated.

    Malformed or non-list payloads degrade to ``[home]`` instead of failing.
    """
    base = normalize_url(base_url)
    pages = [f"{base}/"]
    response = fetch(f"{base}/?rest_route={route}&per_page={per_page}&_fields={fields}")
    if response.get("status") == 200:
        try:
            payload = json.loads(response.get("body", ""))
        except (TypeError, json.JSONDecodeError):
            payload = []
        if isinstance(payload, list):
            for item in payload:
                link = item.get(link_key) if isinstance(item, dict) else None
                if isinstance(link, str) and link not in pages:
                    pages.append(link)
    return pages
