from __future__ import annotations

import re

from ..core.http import HttpClient
from ..core.models import NginxRuntimeInfo

_NGINX_VERSION = re.compile(r"\bnginx(?:/|\s+)(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)


def detect_nginx_runtime(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
) -> NginxRuntimeInfo:
    """Fingerprint a public NGINX edge and observable HTTP/3 advertisement."""
    response = HttpClient(base_url=target_url, timeout=timeout, proxy=proxy).get("/")
    headers = {str(key).lower(): str(value) for key, value in (response.get("headers") or {}).items()}
    server = headers.get("server") or None
    body = str(response.get("body", ""))[:64_000]
    match = _NGINX_VERSION.search(server or "") or _NGINX_VERSION.search(body)
    detected = bool(match or (server and "nginx" in server.lower()))
    version = match.group(1) if match else None
    alt_svc = headers.get("alt-svc", "")
    http3 = bool(re.search(r'(?:^|[,\s])h3(?:-[0-9]+)?\s*=\s*"', alt_svc, re.IGNORECASE))
    source = "/:Server" if server and "nginx" in server.lower() else "/:body" if match else "not-detected"
    return NginxRuntimeInfo(detected, version, source, server, http3)
