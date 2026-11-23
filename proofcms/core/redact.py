"""Shared redaction helpers for console, reports, transcripts and evidence.

Target data and credentials must not cross the report boundary. Keep the
policy in one place so a new output format cannot silently skip it.
"""

from __future__ import annotations

import re
import urllib.parse
from copy import deepcopy
from typing import Any

# Kept for callers that imported the old constant from reporting.console.
SENSITIVE_QUERY_KEYS = {
    "access_token", "api_key", "apikey", "auth", "authorization", "key", "nonce",
    "password", "passwd", "secret", "sig", "signature", "token",
}

_SENSITIVE_PARTS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "authorization",
    "cookie",
    "csrf",
    "xsrf",
    "jwt",
    "privatekey",
    "accesskey",
    "sessionid",
    "sessioncookie",
    "proxyauth",
)
_SENSITIVE_EXACT = {"auth", "key", "sig", "signature", "nonce", "proxy"}


def is_sensitive_key(key: str) -> bool:
    """Return True for keys that commonly carry credentials or session state."""
    normalized = re.sub(r"[^a-z0-9]+", "", str(key).lower())
    if not normalized:
        return False
    if normalized in _SENSITIVE_EXACT:
        return True
    return any(part in normalized for part in _SENSITIVE_PARTS)


def redact_url(value: str) -> str:
    """Redact URL credentials, sensitive query parameters and fragments."""
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return value
    if not parsed.netloc:
        return value
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    has_userinfo = parsed.username is not None or "@" in parsed.netloc
    netloc = ("***@" if has_userinfo else "") + host + (f":{port}" if port else "")
    query = urllib.parse.urlencode(
        [
            (key, "***" if is_sensitive_key(key) else item)
            for key, item in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        ],
        doseq=True,
    )
    fragment = "***" if parsed.fragment else ""
    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, query, fragment))


def redact_text(value: str) -> str:
    """Redact every URL-like token embedded in free-form text."""
    return re.sub(
        r"\b[a-z][a-z0-9+.-]*://[^\s'\"<>]+",
        lambda match: redact_url(match.group(0)),
        value,
        flags=re.IGNORECASE,
    )


def redact_output(value: Any) -> Any:
    """Return a report-safe copy with URLs and sensitive mapping keys redacted."""
    if isinstance(value, dict):
        return {
            key: "***" if is_sensitive_key(str(key)) else redact_output(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_output(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_output(item) for item in value)
    if isinstance(value, str):
        return redact_text(value)
    return deepcopy(value)


__all__ = [
    "SENSITIVE_QUERY_KEYS",
    "is_sensitive_key",
    "redact_output",
    "redact_text",
    "redact_url",
]
