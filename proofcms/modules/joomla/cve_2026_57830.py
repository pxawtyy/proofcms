from __future__ import annotations

import json

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
AJAX_ENDPOINT = "/index.php?option=com_ajax&helix=ultimate&request=task&action=view-media"


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

    proof_url = f"{base}{AJAX_ENDPOINT}"
    response = client.request(
        proof_url,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode({"path": "/images", token: "1"}),
        timeout=timeout,
    )

    try:
        parsed = json.loads(response.get("body", ""))
    except (json.JSONDecodeError, TypeError):
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
            detail=f"view-media returned non-JSON response. HTTP status: {response.get('status')}.",
            action="If Helix Ultimate is installed and <= 2.2.6, manually verify server-side protection.",
        )

    if not isinstance(parsed, dict):
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
            detail=f"view-media returned non-dict JSON response ({type(parsed).__name__}). HTTP status: {response.get('status')}.",
            action="If Helix Ultimate is installed and <= 2.2.6, manually verify server-side protection.",
        )

    folders = parsed.get("folders")
    images = parsed.get("images")
    if parsed.get("status") is True and (images is not None or folders is not None):
        folder_count = len(folders) if isinstance(folders, list) else 0
        image_count = len(images) if isinstance(images, list) else 0
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
            detail=(
                "Safe read-only companion-action probe confirmed missing authorization in Helix Ultimate media AJAX. "
                f"Folders listed: {folder_count}; images listed: {image_count}. "
                f"Token source: {token_source}."
            ),
            action="Restrict unauthenticated AJAX media actions and update Helix Ultimate to 2.2.7 or newer.",
        )

    if parsed.get("success") is True:
        data = parsed.get("data")
        data_count = len(data) if isinstance(data, list) else 0
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
            detail=(
                "Safe read-only companion-action probe confirmed missing authorization in Helix Ultimate media AJAX. "
                "The endpoint returned Joomla's success wrapper. "
                f"Data items returned: {data_count}. Token source: {token_source}."
            ),
            action="Restrict unauthenticated AJAX media actions and update Helix Ultimate to 2.2.7 or newer.",
        )

    parsed_text = str(parsed)
    if "JINVALID_TOKEN" in parsed_text or "token" in parsed_text.lower() and parsed.get("status") is False:
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
            detail=(
                "view-media call was rejected, likely by Joomla token validation. "
                f"Token source: {token_source}. Response: {parsed_text[:300]}"
            ),
            action="Verify plugin version and hardening status manually.",
        )

    if parsed.get("status") is False:
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
            detail=f"view-media call was rejected or did not expose listing: {parsed_text[:300]}",
            action="Verify plugin version and hardening status manually.",
        )

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="INCONCLUSIVE",
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=True,
        proof_url=proof_url,
        detail=f"view-media returned an unexpected JSON response: {str(parsed)[:300]}",
        action="Manually inspect endpoint behavior and Helix Ultimate version.",
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
        "module_version": "1.3.0",
        "last_reviewed": "2026-09-29",
        "updated": "2026-09-29",
        "required_detectors": ["helixultimate"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-57830",
            "https://www.joomshaper.com/documentation/helix-framework/helix-ultimate",
        ],
    }
