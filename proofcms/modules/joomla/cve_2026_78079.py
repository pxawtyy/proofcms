from __future__ import annotations

import base64
import re
import secrets
import urllib.parse
from typing import Any

from ...core.args import aggressive_value
from ...core.http import HttpClient, form_encode, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-78079"
NAME = "Helix Ultimate authenticated open redirect"
COMPONENT = "Helix Ultimate Framework"
AFFECTED_RULE = "Helix Ultimate 1.0 through 2.2.9; fixed in 2.2.10"
PATCHED_VERSION = "2.2.10"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]
LOGIN_PATH = "/index.php/component/users/login"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    fixed = parse_version_safe(PATCHED_VERSION)
    if parsed is None or fixed is None:
        return "INCONCLUSIVE"
    return "LIKELY_VULNERABLE" if parsed < fixed else "PATCHED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    helix = (plugins or {}).get("helixultimate", {})
    if not helix.get("found"):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_DETECTED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail="Helix Ultimate was not detected via template or plugin routes.",
            action="Verify manually if Helix Ultimate is installed under a non-public or custom path.",
        )
    version = helix.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected Helix Ultimate {version}, which is in the affected range."
        action = "Upgrade Helix Ultimate to 2.2.10 or newer."
        confidence = "HIGH"
    elif status == "PATCHED":
        detail = f"Detected Helix Ultimate {version}, which includes the open-redirect fix."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "Helix Ultimate was detected, but its version could not be determined."
        action = "Determine the installed version and upgrade to 2.2.10 or newer."
        confidence = "MEDIUM"
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence=confidence,
        component=COMPONENT,
        component_version=version,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=detail,
        action=action,
    )


def _login(client: HttpClient, base: str, username: str, password: str, timeout: int) -> bool:
    page = client.get(f"{base}{LOGIN_PATH}", timeout=timeout)
    token = re.search(r'name="([a-f0-9]{32})" value="1"', page.get("body", "") or "")
    if not token:
        return False
    response = client.request(
        f"{base}/index.php?option=com_users&task=user.login",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode({
            "username": username,
            "password": password,
            "remember": "0",
            "return": "",
            token.group(1): "1",
        }),
        timeout=timeout,
        follow_redirects=False,
    )
    location = str((response.get("headers") or {}).get("Location") or "")
    return response.get("status") in (301, 302, 303) and "login" not in location.lower()


def run_safe_probe(
    target_url: str,
    username: str | None = None,
    password: str | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    base = normalize_url(target_url)
    if not username or not password:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="BLOCKED_EXTERNAL",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=False,
            proof_url=f"{base}{LOGIN_PATH}",
            detail=(
                "The helixreturn redirect requires a logged-in user; pass "
                "--aggressive-arg username=... password=... from the lab fixture. "
                "Nothing was sent."
            ),
            action="Re-run with lab credentials on an authorized target.",
        )
    client = HttpClient(timeout=timeout, proxy=proxy)
    preflight = client.get(f"{base}/", timeout=timeout)
    if is_transport_error(preflight):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="ERROR",
            confidence="LOW",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=f"{base}/",
            detail=f"The target could not be reached ({transport_error_detail(preflight)}).",
            action="Retry when the target is reachable.",
        )
    if not _login(client, base, username, password, timeout):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=f"{base}{LOGIN_PATH}",
            detail="The front-end login did not establish a session; the redirect was not tested.",
            action="Verify the lab credentials and the front-end login route.",
        )
    marker = secrets.token_hex(6)
    destination = f"https://example.invalid/proofcms-open-redirect-{marker}"
    encoded = base64.b64encode(destination.encode()).decode()
    proof_url = f"{base}/?helixreturn={urllib.parse.quote(encoded, safe='')}"
    response = client.request(proof_url, method="GET", timeout=timeout, follow_redirects=False)
    location = str((response.get("headers") or {}).get("Location") or "")
    evidence = {
        "logged_in": True,
        "destination": destination,
        "status": response.get("status"),
        "location": location or None,
    }
    if response.get("status") in {301, 302, 303, 307, 308} and location == destination:
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
            evidence=evidence,
            detail=(
                "An authenticated request carrying a Base64-encoded external helixreturn URL was "
                "answered with a redirect to that external destination."
            ),
            action="Upgrade Helix Ultimate to 2.2.10 or newer.",
        )
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
        evidence=evidence,
        detail=(
            "The external return URL was not reflected as a redirect "
            f"(HTTP {response.get('status')}, Location={location or 'absent'})."
        ),
        action="Upgrade versions through 2.2.9 even when active verification is inconclusive.",
    )


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    plugins: dict[str, Any] | None = None,
    aggressive_command: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Finding:
    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode != "safe":
        passive.detail += " This module supports only the non-following open-redirect proof."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        passive.detail += " Safe proof skipped because Helix Ultimate was not detected as potentially affected."
        return passive
    result = run_safe_probe(
        target_url,
        username=aggressive_value(aggressive_args, aggressive_command, "username"),
        password=aggressive_value(aggressive_args, aggressive_command, "password"),
        timeout=timeout,
        proxy=proxy,
    )
    result.component_version = passive.component_version
    return result


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": ["*"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "vulnerability_type": "Open Redirect",
        "module_version": "1.1.0",
        "last_reviewed": "2026-11-12",
        "updated": "2026-11-12",
        "required_detectors": ["helixultimate"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-78079",
            "https://www.joomshaper.com/joomla-templates/helixultimate",
        ],
    }
