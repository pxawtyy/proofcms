from __future__ import annotations

import ipaddress
import re
import secrets
import urllib.parse

from ..core.http import HttpClient, is_baseline_match, probe_target_baseline
from ..core.models import PHPRuntimeInfo

_PHP_VERSION = re.compile(r"(?:PHP/|PHP(?:\s+Version)?\s+)(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
_PHPINFO_TITLE = re.compile(r"<title>\s*PHP[^<]*phpinfo\(\)", re.IGNORECASE)
_PHPINFO_VERSION = re.compile(r"PHP\s+Version\s*</td>\s*<td[^>]*>\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE)
_PHPINFO_SERVER = re.compile(r"SERVER_SOFTWARE.{0,800}?\b([^<\s]+/[^<\s]+)", re.IGNORECASE | re.DOTALL)
_PHPINFO_ADDR = re.compile(r"SERVER_ADDR.{0,800}?(\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE | re.DOTALL)


def _phpinfo_data(response: dict) -> tuple[str | None, str | None, str | None]:
    if response.get("status") != 200:
        return None, None, None
    body = str(response.get("body", ""))[:512_000]
    if not _PHPINFO_TITLE.search(body) and "PHP Version" not in body:
        return None, None, None
    plain = re.sub(r"<[^>]+>", " ", body)
    plain = re.sub(r"\s+", " ", plain)
    version_match = _PHPINFO_VERSION.search(body) or _PHP_VERSION.search(plain)
    server_match = _PHPINFO_SERVER.search(plain)
    addr_match = _PHPINFO_ADDR.search(plain)
    return (
        version_match.group(1) if version_match else None,
        server_match.group(1) if server_match else None,
        addr_match.group(1) if addr_match else None,
    )


def _probe_disclosed_origin(
    target_url: str,
    origin_ip: str | None,
    path: str,
    timeout: int,
    proxy: str | None,
) -> tuple[bool, str | None]:
    if not origin_ip:
        return False, None
    try:
        address = ipaddress.ip_address(origin_ip)
    except ValueError:
        return False, None
    if not address.is_global:
        return False, None
    parsed = urllib.parse.urlsplit(target_url)
    if not parsed.hostname:
        return False, None
    base_path = parsed.path.rstrip("/")
    direct = HttpClient(
        base_url=f"https://{address.compressed}{base_path}",
        timeout=timeout,
        proxy=proxy,
        verify_tls=False,
    )
    response = direct.get(
        path,
        headers={"Host": parsed.hostname},
        timeout=timeout,
    )
    if response.get("status", 0) <= 0:
        return False, None
    headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
    server = headers.get("server")
    if server and "cloudflare" not in server.lower():
        return True, server
    return False, server


def detect_php_runtime(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
) -> PHPRuntimeInfo:
    """Fingerprint the web-facing PHP runtime without creating files or invoking phpinfo()."""
    client = HttpClient(base_url=target_url, timeout=timeout, proxy=proxy)
    baseline = probe_target_baseline(target_url, timeout=timeout, proxy=proxy)
    server: str | None = None
    first_php_path = "/index.php"
    php_session_source: str | None = None
    try:
        phpinfo_response = client.get("phpinfo.php")
    except Exception:  # noqa: BLE001 - optional disclosure probe must not break runtime detection
        phpinfo_response = {"status": 0, "body": ""}
    phpinfo_version, phpinfo_server, origin_ip = _phpinfo_data(phpinfo_response)
    phpinfo_exposed = phpinfo_version is not None or phpinfo_server is not None
    origin_reachable, origin_server = _probe_disclosed_origin(
        target_url,
        origin_ip,
        "phpinfo.php",
        timeout,
        proxy,
    ) if phpinfo_exposed else (False, None)
    if phpinfo_exposed:
        return PHPRuntimeInfo(
            True,
            phpinfo_version,
            "/phpinfo.php:PHP Version" if phpinfo_version else "/phpinfo.php:phpinfo",
            phpinfo_server,
            "/phpinfo.php",
            True,
            "/phpinfo.php",
            int(phpinfo_response.get("body_len") or len(str(phpinfo_response.get("body", "")).encode("utf-8"))),
            origin_ip,
            origin_reachable,
            origin_server,
        )
    for path in ("/", "/index.php", "/administrator/index.php", "/wp-login.php"):
        response = client.get(path)
        if not response.get("status", 0):
            continue
        lowered_headers = {str(key).lower(): value for key, value in (response.get("headers") or {}).items()}
        server_header = str(lowered_headers.get("server", ""))
        server = server or server_header or None
        for source_name, value in (
            ("X-Powered-By", str(lowered_headers.get("x-powered-by", ""))),
            ("Server", server_header),
        ):
            match = re.search(r"PHP/(\d+\.\d+(?:\.\d+)?)", value, re.IGNORECASE)
            if match:
                return PHPRuntimeInfo(True, match.group(1), f"{path}:{source_name}", server, path)
        body = str(response.get("body", ""))
        error_context = re.search(
            r"(?:fatal error|warning|stack trace|php version|powered by php).{0,160}",
            body[:256_000],
            re.IGNORECASE | re.DOTALL,
        )
        match = _PHP_VERSION.search(error_context.group(0)) if error_context else None
        if match:
            return PHPRuntimeInfo(True, match.group(1), f"{path}:body", server, path)
        if "PHPSESSID" in str(lowered_headers.get("set-cookie", "")):
            first_php_path = path
            php_session_source = f"{path}:PHPSESSID"

    if php_session_source:
        return PHPRuntimeInfo(True, None, php_session_source, server, first_php_path)

    # Joomla's configuration.php normally executes to an empty response. A 200
    # alone is not evidence because many Joomla deployments rewrite missing paths
    # to the homepage, so compare it with a random .php file in the same directory.
    configuration = client.get("/configuration.php")
    missing = client.get(f"/_proofcms_missing_{secrets.token_hex(8)}.php")
    configuration_body = str(configuration.get("body", ""))
    missing_body = str(missing.get("body", ""))
    if (
        configuration.get("status") == 200
        and not configuration.get("redirected")
        and len(configuration_body.encode("utf-8", "replace")) <= 32
        and not is_baseline_match(configuration, baseline)
        and (
            missing.get("status") != 200
            or missing.get("body_hash") != configuration.get("body_hash")
            or len(missing_body.encode("utf-8", "replace")) > 32
        )
    ):
        return PHPRuntimeInfo(True, None, "/configuration.php:executed-empty", server, "/configuration.php")
    return PHPRuntimeInfo(False, None, "not-detected", server, first_php_path)
