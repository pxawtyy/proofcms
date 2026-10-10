from __future__ import annotations

import html
import re

from ..core.http import HttpClient
from ..core.models import NginxRuntimeInfo

_NGINX_VERSION = re.compile(r"\bnginx(?:/|\s+)(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
_HTTP3_ALT_SVC = re.compile(r'(?:^|[,]?\s*)h3(?:-[0-9]+)?\s*=\s*"', re.IGNORECASE)
_PHPINFO_SIGNATURE = re.compile(r"(?:<title>\s*PHP[^<]*phpinfo\(\)|PHP Version)", re.IGNORECASE)
_SERVER_SOFTWARE = re.compile(
    r"SERVER_SOFTWARE.{0,800}?\bnginx(?:/|\s+)(\d+\.\d+(?:\.\d+)?)",
    re.IGNORECASE | re.DOTALL,
)


def _headers(response: dict) -> dict[str, str]:
    return {str(key).lower(): str(value) for key, value in (response.get("headers") or {}).items()}


def _phpinfo_nginx_version(response: dict) -> str | None:
    """Return SERVER_SOFTWARE's NGINX version only from a genuine phpinfo page."""
    if response.get("status") != 200:
        return None
    body = str(response.get("body", ""))[:512_000]
    if not _PHPINFO_SIGNATURE.search(body):
        return None
    plain = html.unescape(re.sub(r"<[^>]+>", " ", body))
    plain = re.sub(r"\s+", " ", plain)
    match = _SERVER_SOFTWARE.search(plain)
    return match.group(1) if match else None


def detect_nginx_runtime(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
) -> NginxRuntimeInfo:
    """Fingerprint public NGINX evidence without confusing a CDN edge for the origin."""
    client = HttpClient(base_url=target_url, timeout=timeout, proxy=proxy)
    response = client.get("/")
    headers = _headers(response)
    response_server = headers.get("server") or None
    body = str(response.get("body", ""))[:64_000]
    direct_nginx = bool(response_server and "nginx" in response_server.lower())
    match = _NGINX_VERSION.search(response_server or "") if direct_nginx else None
    match = match or _NGINX_VERSION.search(body)
    version = match.group(1) if match else None
    detected = bool(match or direct_nginx)
    source = "/:Server" if direct_nginx else "/:body" if match else "not-detected"

    edge_server = None if direct_nginx else response_server
    alt_svc_http3 = bool(_HTTP3_ALT_SVC.search(headers.get("alt-svc", "")))
    http3 = alt_svc_http3 if direct_nginx else False
    edge_http3 = alt_svc_http3 if edge_server else False
    server = response_server if direct_nginx else None

    # Base-relative resolution covers installations below a path, such as
    # /site/phpinfo.php. A strict phpinfo signature prevents false evidence.
    if version is None:
        phpinfo_response = client.get("phpinfo.php")
        phpinfo_version = _phpinfo_nginx_version(phpinfo_response)
        if phpinfo_version:
            detected = True
            version = phpinfo_version
            server = f"nginx/{phpinfo_version}"
            source = "/phpinfo.php:SERVER_SOFTWARE"

    return NginxRuntimeInfo(
        detected,
        version,
        source,
        server,
        http3,
        edge_server,
        edge_http3,
    )
