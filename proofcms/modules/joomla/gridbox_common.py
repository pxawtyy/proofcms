"""Shared helpers for the Gridbox (com_gridbox) CVE modules.

The 2.20.2 CVE set shares one lab and one detection path: the public
component manifest at /administrator/components/com_gridbox/gridbox.xml
reports the exact Gridbox version. Helpers here keep the per-CVE modules
small and consistent.
"""

from __future__ import annotations

import json
import re
import secrets
import string
from typing import Any

from ...core.http import HttpClient, form_encode
from ...core.models import Finding
from ...core.versions import parse_version_required, parse_version_safe

LOGIN_PAGE = "/index.php/component/users/login?Itemid=101"
PROFILE_EDIT = "/index.php?option=com_users&view=profile&layout=edit"
ADMIN_LOGIN = "/administrator/index.php"


def gridbox_info(plugins: dict | None) -> dict[str, Any]:
    return (plugins or {}).get("gridbox", {}) or {}


def version_status(version: str | None, fixed: str = "2.20.1") -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    if parsed < parse_version_required(fixed):
        return "LIKELY_VULNERABLE"
    return "PATCHED"


def passive_gridbox(
    plugins: dict | None,
    *,
    cve: str,
    name: str,
    component: str,
    affected_rule: str,
    fixed_rule: str,
    fixed: str,
    affected_detail: str,
    patched_detail: str,
    action: str,
) -> Finding:
    info = gridbox_info(plugins)
    found = bool(info.get("found"))
    version = info.get("version")
    if not found:
        return Finding(
            cve=cve, name=name, status="NOT_DETECTED", confidence="MEDIUM",
            component=component, component_version=None, affected_rule=affected_rule,
            exploit_available=True,
            detail="Gridbox was not detected through its public component manifest or asset paths.",
            action="Component not detected via standard routes; verify manually if installed at another path.",
        )
    status = version_status(version, fixed)
    confidence = "HIGH" if status in {"LIKELY_VULNERABLE", "PATCHED"} else "MEDIUM"
    detail = affected_detail if status == "LIKELY_VULNERABLE" else patched_detail
    if status == "INCONCLUSIVE":
        detail = f"Gridbox was detected ({info.get('source') or 'unknown'}) but its version could not be determined."
    return Finding(
        cve=cve, name=name, status=status, confidence=confidence,
        component=component, component_version=version, affected_rule=affected_rule,
        exploit_available=True, detail=detail, action=action,
    )


def json_body(response: dict[str, Any]) -> dict[str, Any]:
    try:
        parsed = json.loads(response.get("body") or "{}")
    except (ValueError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def token(page: str) -> str | None:
    match = re.search(r'type="hidden" name="([a-f0-9]{32})" value="1"', page)
    return match.group(1) if match else None


def frontend_login(
    client: HttpClient, base: str, user: str, password: str, timeout: int
) -> bool:
    page = client.get(f"{base}{LOGIN_PAGE}", timeout=timeout)
    tok = token(page.get("body", "") or "")
    if not tok:
        return False
    client.request(
        f"{base}/index.php?option=com_users&task=user.login",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode({
            "username": user, "password": password, "remember": "no",
            "return": "", tok: "1",
        }),
        timeout=timeout,
        follow_redirects=False,
    )
    return True


def admin_login(
    client: HttpClient, base: str, user: str, password: str, timeout: int
) -> bool:
    page = client.get(f"{base}{ADMIN_LOGIN}", timeout=timeout)
    tok = token(page.get("body", "") or "")
    if not tok:
        return False
    client.request(
        f"{base}{ADMIN_LOGIN}",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode({
            "username": user, "passwd": password, "option": "com_login",
            "task": "login", "return": "aW5kZXgucGhw", tok: "1",
        }),
        timeout=timeout,
        follow_redirects=False,
    )
    return True


def admin_dashboard(client: HttpClient, base: str, timeout: int) -> bool:
    page = client.get(f"{base}{ADMIN_LOGIN}", timeout=timeout)
    body = page.get("body", "") or ""
    return (
        'name="passwd"' not in body
        and ("com_cpanel" in body or "COM_CPANEL" in body or "logout" in body.lower())
    )


def profile_identity(client: HttpClient, base: str, timeout: int) -> str | None:
    page = client.get(f"{base}{PROFILE_EDIT}", timeout=timeout)
    match = re.search(r'name="jform\[username\]"[^>]*value="([^"]*)"', page.get("body", "") or "")
    return match.group(1) if match else None


def random_suffix(length: int = 8) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def random_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%"
    return "Gb!" + "".join(secrets.choice(alphabet) for _ in range(length))
