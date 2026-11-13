"""GeneXus platform / generated-application detector.

GeneXus-generated web applications expose a small set of stable markers:
``gxajax`` endpoints, ``gxcfg.js`` runtime configuration, ``GXState``
hidden fields and ``gx*`` cookies.  The detector is deliberately
conservative: a generic page that merely mentions "GeneXus" is not enough.
"""

from __future__ import annotations

import re
from typing import Any

from ..core.http import HttpClient

_BODY_MARKERS = (
    "gxajax",
    "gxcfg.js",
    "gxcfg",
    "gxstate",
    "gxmetadata",
    "gxresource",
    "gx.ws",
)
_COOKIE_MARKERS = ("gxstate", "gxsession", "gxajax", "gxbr")
_VERSION_PATTERNS = (
    re.compile(r"""gx\.version\s*=\s*["']([^"']+)["']""", re.IGNORECASE),
    re.compile(r"""GeneXus(?:\s+X\s+Evolution)?\s*([0-9]+(?:\.[0-9]+){1,3})""", re.IGNORECASE),
    re.compile(r"""GX_?VERSION["']?\s*[:=]\s*["']([0-9]+(?:\.[0-9]+){1,3})["']""", re.IGNORECASE),
)


def _header(headers: dict[str, Any], name: str) -> str:
    wanted = name.lower()
    for key, value in (headers or {}).items():
        if str(key).lower() == wanted:
            return str(value)
    return ""


def _find_version(text: str) -> str | None:
    for pattern in _VERSION_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(1)
    return None


def detect_genexus(target_url: str, timeout: int = 12, proxy: str | None = None) -> dict[str, Any]:
    """Return ``{detected, version, source, evidence, raw}`` for a GeneXus app."""
    client = HttpClient(base_url=target_url, timeout=timeout, proxy=proxy)
    home = client.get("/")
    body = str(home.get("body") or "")
    lowered = body.lower()
    headers = home.get("headers") or {}
    evidence: list[str] = []

    for marker in _BODY_MARKERS:
        if marker in lowered:
            evidence.append(f"body:{marker}")

    set_cookie = _header(headers, "set-cookie").lower()
    for marker in _COOKIE_MARKERS:
        if marker in set_cookie:
            evidence.append(f"cookie:{marker}")

    powered = _header(headers, "x-powered-by")
    server = _header(headers, "server")
    if "genexus" in powered.lower() or "genexus" in server.lower():
        evidence.append("header:genexus")

    version = _find_version(body)
    source = "body" if version else ""

    if "gxcfg" in lowered:
        config = client.get("/gxcfg.js")
        config_body = str(config.get("body") or "")
        if config_body and config.get("status") == 200:
            evidence.append("path:/gxcfg.js")
            config_version = _find_version(config_body)
            if config_version:
                version = config_version
                source = "/gxcfg.js"

    detected = bool(evidence)
    return {
        "detected": detected,
        "version": version,
        "source": source or ("body" if detected else "not-detected"),
        "evidence": evidence,
        "raw": body[:2000],
    }
