from __future__ import annotations

import re
import secrets

from ..core.http import HttpClient, is_baseline_match, probe_target_baseline
from ..core.models import PHPRuntimeInfo

_PHP_VERSION = re.compile(r"(?:PHP/|PHP(?:\s+Version)?\s+)(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)


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
