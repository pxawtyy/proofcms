"""Shared authenticated-session helpers for Joomla and WordPress logins.

Three modules re-implemented the same flows: Joomla ``/administrator/``
login with its session-bound CSRF token (media probe, registration probe,
CVE-2026-90915) and WordPress ``wp-login.php`` login (Essential Addons).
Both live here now; the module-level originals remain as thin wrappers so
existing unit tests keep patching the same names.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from .http import HttpClient, normalize_url
from .probes import extract_csrf_from_html

JOOMLA_ADMIN_PATH = "/administrator/index.php"
JOOMLA_LOGIN_RETURN = "aW5kZXgucGhw"
JOOMLA_LOGGED_IN_MARKERS = ("com_cpanel", "Dashboard")
WP_LOGIN_PATH = "/wp-login.php"


def joomla_login_fields(username: str, password: str, token: str) -> dict[str, Any]:
    """Return the POST fields for a Joomla administrator login."""
    return {
        "username": username,
        "passwd": password,
        "option": "com_login",
        "task": "login",
        "return": JOOMLA_LOGIN_RETURN,
        token: "1",
    }


def is_joomla_logged_in(body: str, status: int | None = 200) -> bool:
    """Return True when a login response shows the admin dashboard.

    ``status=None`` skips the HTTP check (the legacy media-probe login only
    looked for dashboard markers).
    """
    if status is not None and status != 200:
        return False
    return any(marker in body for marker in JOOMLA_LOGGED_IN_MARKERS)


def joomla_admin_login(
    client: HttpClient,
    base_url: str = "",
    username: str = "",
    password: str = "",
    timeout: int = 12,
    strict_status: bool = True,
) -> bool:
    """Log a session client into the Joomla administrator.

    Fetches the login page for its session-bound CSRF token, posts the
    credentials, and reports whether the dashboard markers appear. Any
    transport failure or missing token is a plain ``False``. ``base_url``
    is only used to validate the target shape and may be empty when the
    client already carries its base (e.g. in unit tests). Pass
    ``strict_status=False`` to accept dashboard markers regardless of the
    login response status (legacy media-probe behavior).
    """
    if base_url:
        # Validate the target shape; the client already carries the base used
        # for the relative administrator path.
        _ = normalize_url(base_url)
    page = client.get(JOOMLA_ADMIN_PATH, timeout=timeout)
    token = extract_csrf_from_html(str(page.get("body", "")))
    if not token:
        return False
    response = client.post(
        JOOMLA_ADMIN_PATH,
        fields=joomla_login_fields(username, password, token),
        timeout=timeout,
    )
    status: int | None = int(response.get("status", 0) or 0) if strict_status else None
    return is_joomla_logged_in(str(response.get("body", "")), status)


def verify_joomla_admin_login(
    target_url: str,
    *,
    username: str,
    password: str,
    timeout: int = 12,
    proxy: str | None = None,
) -> dict[str, Any]:
    """Attempt an administrator login and describe the outcome.

    Returns ``{"logged_in": bool, "status": int, "final_url": str}`` with an
    additional ``reason`` key when no CSRF token was found.
    """
    base = normalize_url(target_url)
    client = HttpClient(base_url=base, timeout=timeout, proxy=proxy)
    page = client.get(JOOMLA_ADMIN_PATH, timeout=timeout)
    token = extract_csrf_from_html(str(page.get("body", "")))
    if not token:
        return {
            "logged_in": False,
            "reason": "No administrator CSRF token was found.",
            "status": page.get("status", 0),
        }
    response = client.post(
        JOOMLA_ADMIN_PATH,
        fields=joomla_login_fields(username, password, token),
        timeout=timeout,
    )
    body = str(response.get("body", ""))
    return {
        "logged_in": is_joomla_logged_in(body, int(response.get("status", 0) or 0)),
        "status": response.get("status", 0),
        "final_url": response.get("final_url", ""),
    }


def wordpress_login_fields(username: str, password: str) -> dict[str, Any]:
    """Return the POST fields for a WordPress ``wp-login.php`` login."""
    return {
        "log": username,
        "pwd": password,
        "wp-submit": "Log In",
        "redirect_to": "/wp-admin/",
        "testcookie": "1",
    }


def wordpress_admin_login(
    client: HttpClient,
    base_url: str = "",
    username: str = "",
    password: str = "",
    timeout: int = 12,
) -> tuple[bool, str]:
    """Log a session client into WordPress; return ``(ok, final_url)``."""
    base = normalize_url(base_url) if base_url else ""
    client.get(WP_LOGIN_PATH, timeout=timeout)
    login = client.post(
        WP_LOGIN_PATH,
        fields=wordpress_login_fields(username, password),
        timeout=timeout,
    )
    final_url = str(login.get("final_url") or "")
    status = int(login.get("status") or 0)
    if status and status not in {200, 302, 303}:
        return False, final_url
    if base and urlsplit(final_url).netloc.lower() != urlsplit(base).netloc.lower():
        return False, final_url
    body = str(login.get("body", ""))
    # Language-independent WordPress admin markers; "Dashboard" alone misses
    # localized installations (the client already asks for pt-BR).
    markers = ("wpadminbar", "wp-admin-bar", "wp-admin/wp-admin.css", "/wp-admin/", "dashboard")
    return any(marker.lower() in body.lower() for marker in markers), final_url
