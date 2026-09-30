from __future__ import annotations

import re

from ..core.http import HttpClient
from ..core.models import PHPRuntimeInfo

_PHP_VERSION = re.compile(r"(?:PHP/|PHP(?:\s+Version)?\s+)(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)


def detect_php_runtime(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
) -> PHPRuntimeInfo:
    """Fingerprint the web-facing PHP runtime without creating files or invoking phpinfo()."""
    client = HttpClient(base_url=target_url, timeout=timeout, proxy=proxy)
    observations: list[tuple[str, dict]] = []
    for path in ("/", "/index.php", "/administrator/index.php", "/wp-login.php"):
        response = client.get(path)
        if response.get("status", 0):
            observations.append((path, response))

    server: str | None = None
    first_php_path = "/index.php"
    php_session_source: str | None = None
    for path, response in observations:
        headers = response.get("headers") or {}
        powered = str(headers.get("X-Powered-By", headers.get("x-powered-by", "")))
        server_header = str(headers.get("Server", headers.get("server", "")))
        server = server or server_header or None
        for source_name, value in (("X-Powered-By", powered), ("Server", server_header)):
            match = re.search(r"PHP/(\d+\.\d+(?:\.\d+)?)", value, re.IGNORECASE)
            if match:
                return PHPRuntimeInfo(True, match.group(1), f"{path}:{source_name}", server, path)
        body = str(response.get("body", ""))
        match = _PHP_VERSION.search(body[:256_000])
        if match:
            return PHPRuntimeInfo(True, match.group(1), f"{path}:body", server, path)
        if "PHPSESSID" in str(headers.get("Set-Cookie", headers.get("set-cookie", ""))):
            first_php_path = path
            php_session_source = f"{path}:PHPSESSID"

    if php_session_source:
        return PHPRuntimeInfo(True, None, php_session_source, server, first_php_path)
    return PHPRuntimeInfo(False, None, "not-detected", server, first_php_path)
