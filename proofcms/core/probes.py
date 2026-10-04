from __future__ import annotations

import random
import re
import string

from .http import normalize_url, request

CSRF_TOKEN_PATTERNS = [
    re.compile(r'name=["\']([a-f0-9]{32})["\'][^>]{0,160}value=["\']1["\']', re.IGNORECASE),
    re.compile(r'value=["\']1["\'][^>]{0,160}name=["\']([a-f0-9]{32})["\']', re.IGNORECASE),
    re.compile(r'csrf\.token["\']?\s*:\s*["\']([a-f0-9]{32})["\']', re.IGNORECASE),
    re.compile(r'["\']csrf\.token["\']\s*:\s*["\']([a-f0-9]{32})["\']', re.IGNORECASE),
]

CSRF_CANDIDATE_PATHS = [
    "/index.php?option=com_users&view=login",
    "/index.php?option=com_users&view=registration",
    "/index.php?option=com_users&view=reset",
    "/index.php?option=com_users&view=remind",
    "/",
    "/index.php?option=com_contact",
    "/index.php?option=com_contact&view=contact",
    "/administrator/",
    "/administrator/index.php",
]


def rand_str(size: int = 8) -> str:
    """Generate a random alphanumeric string."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=size))


def extract_csrf_from_html(html: str) -> str | None:
    """Extract 32-character Joomla CSRF token from HTML source."""
    if not html:
        return None
    for pattern in CSRF_TOKEN_PATTERNS:
        match = pattern.search(html)
        if match:
            return match.group(1)
    return None


def extract_csrf_candidates_from_html(html: str) -> list[str]:
    """Return distinct Joomla tokens, preferring session-bound hidden inputs."""
    tokens: list[str] = []
    for pattern in CSRF_TOKEN_PATTERNS:
        for match in pattern.finditer(html or ""):
            token = match.group(1)
            if token not in tokens:
                tokens.append(token)
    return tokens


def find_anon_csrf_token(
    base_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    paths: list[str] | None = None,
    requester=None,
) -> tuple[str | None, str | None]:
    """
    Search known public candidate paths for an anonymous CSRF token.
    Returns: (token, found_url) or (None, None).
    """
    base = normalize_url(base_url)
    fetch = requester or (lambda url, timeout=timeout: request(url, timeout=timeout, proxy=proxy))
    for path in paths or CSRF_CANDIDATE_PATHS:
        url = f"{base}{path if path.startswith('/') else '/' + path}"
        response = fetch(url, timeout=timeout)
        if response.get("status") not in (200, 301, 302, 303):
            continue
        token = extract_csrf_from_html(response.get("body", ""))
        if token:
            return token, url
    return None, None
