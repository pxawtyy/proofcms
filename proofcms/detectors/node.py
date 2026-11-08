from __future__ import annotations

import re

from ..core.http import HttpClient
from ..core.models import NodeRuntimeInfo

_VERSION = re.compile(r"(?:node(?:\.js)?[/\s:v]|v)(\d+\.\d+\.\d+)", re.IGNORECASE)
_FRAMEWORKS = {
    "express": "Express",
    "fastify": "Fastify",
    "koa": "Koa",
    "nest": "NestJS",
    "next.js": "Next.js",
    "nextjs": "Next.js",
}
_SESSION_COOKIE_MARKERS = ("connect.sid", "express:sess", "koa.sess", "next-auth.session-token")


def _headers(response: dict) -> dict[str, str]:
    return {str(key).lower(): str(value) for key, value in (response.get("headers") or {}).items()}


def detect_node_runtime(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
) -> NodeRuntimeInfo:
    """Fingerprint Node.js from explicit HTTP evidence without guessing from generic HTML."""
    client = HttpClient(base_url=target_url, timeout=timeout, proxy=proxy)
    response = client.get("/")
    headers = _headers(response)
    server = headers.get("server") or None
    powered = headers.get("x-powered-by", "")
    server_match = _VERSION.search(server or "")
    powered_match = _VERSION.search(powered)
    version_match = server_match or powered_match
    framework = None
    lowered_powered = powered.lower()
    for marker, name in _FRAMEWORKS.items():
        if marker in lowered_powered:
            framework = name
            break
    node_header = any(
        marker in value.lower()
        for marker in ("node", "express", "fastify", "koa", "nest", "next.js", "nextjs")
        for value in (server or "", powered)
    )
    session_cookie = any(marker in headers.get("set-cookie", "").lower() for marker in _SESSION_COOKIE_MARKERS)
    detected = bool(version_match or node_header or framework or session_cookie)
    if version_match:
        source = "/:Server" if server_match else "/:X-Powered-By"
        version = version_match.group(1)
    elif framework:
        source = "/:X-Powered-By"
        version = None
    elif session_cookie:
        source = "/:Set-Cookie"
        version = None
    elif node_header:
        source = "/:Server"
        version = None
    else:
        source = "not-detected"
        version = None
    return NodeRuntimeInfo(detected, version, source, server, framework, session_cookie)


__all__ = ["detect_node_runtime"]
