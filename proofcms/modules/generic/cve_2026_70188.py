from __future__ import annotations

import socket
import ssl
import time
import urllib.parse
from typing import Any

from ...core.http import tls_verification_enabled
from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_required, parse_version_safe
from .aspnet_common import core_runtime_gate

CVE_ID = "CVE-2026-70188"
NAME = "ASP.NET Core Kestrel HTTP/2 trailer newline smuggling"
RULE = (
    "ASP.NET Core 8.0 before 8.0.32, 9.0 before 9.0.21, 10.0 before 10.0.13, "
    "and 11.0 before 11.0.0-rc2"
)
FIXED_RULE = "Upgrade ASP.NET Core to 8.0.32, 9.0.21, 10.0.13, 11.0.0-rc2, or newer"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]


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


def _frames(buf: bytes) -> list[tuple[int, bytes]]:
    frames: list[tuple[int, bytes]] = []
    pos = 0
    while pos + 9 <= len(buf):
        length = int.from_bytes(buf[pos : pos + 3], "big")
        if pos + 9 + length > len(buf):
            break
        frames.append((buf[pos + 3], buf[pos + 9 : pos + 9 + length]))
        pos += 9 + length
    return frames


def _status_from_headers(payload: bytes) -> int | None:
    if not payload:
        return None
    return {0x88: 200, 0x8C: 400, 0x89: 204, 0x8D: 404, 0x8E: 500}.get(payload[0])


def _probe(host: str, port: int, value: str, use_tls: bool, timeout: float) -> dict[str, Any]:
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from hyperframe.frame import HeadersFrame

    raw = socket.create_connection((host, port), timeout=timeout)
    sock: socket.socket = raw
    if use_tls:
        context = ssl.create_default_context()
        if not tls_verification_enabled():
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["h2"])
        sock = context.wrap_socket(raw, server_hostname=host)
    else:
        sock = raw

    conn = H2Connection(config=H2Configuration(client_side=True))
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    sock.settimeout(0.5)
    try:
        data = sock.recv(65535)
        if data:
            conn.receive_data(data)
            sock.sendall(conn.data_to_send())
    except TimeoutError:
        pass

    scheme = "https" if use_tls else "http"
    conn.send_headers(
        1,
        [
            (":method", "GET"),
            (":path", "/"),
            (":scheme", scheme),
            (":authority", host),
            ("te", "trailers"),
        ],
        end_stream=False,
    )
    sock.sendall(conn.data_to_send())
    conn.send_data(1, b"x", end_stream=False)
    sock.sendall(conn.data_to_send())

    block = conn.encoder.encode([("x-proofcms", value)])
    trailer = HeadersFrame(1)
    trailer.data = block
    trailer.flags.add("END_HEADERS")
    trailer.flags.add("END_STREAM")
    sock.sendall(trailer.serialize())

    sock.settimeout(0.3)
    buf = b""
    closed = False
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data = sock.recv(65535)
        except TimeoutError:
            continue
        except (ConnectionResetError, ssl.SSLError, OSError):
            closed = True
            break
        if not data:
            closed = True
            break
        buf += data
        # Only GOAWAY ends the read early. A RST_STREAM with NO_ERROR is Kestrel's
        # normal "stop sending the body" reset and can arrive before the GOAWAY.
        if any(ftype == 7 for ftype, _ in _frames(buf)):
            break

    sock.close()
    frames = _frames(buf)
    types = [ftype for ftype, _ in frames]
    statuses = [
        _status_from_headers(payload)
        for ftype, payload in frames
        if ftype == 1
    ]
    statuses = [status for status in statuses if status is not None]
    goaway_errors = [
        int.from_bytes(payload[4:8], "big")
        for ftype, payload in frames
        if ftype == 7 and len(payload) >= 8
    ]
    protocol_goaway = any(error != 0 for error in goaway_errors)
    status_400 = 400 in statuses
    status_200 = 200 in statuses

    return {
        "types": types,
        "statuses": statuses,
        "goaway_errors": goaway_errors,
        "closed": closed,
        "rejected": protocol_goaway or status_400 or (closed and not status_200),
        "accepted": status_200 and not protocol_goaway,
    }


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> dict[str, Any]:
    if proxy:
        return {"inconclusive": True, "reason": "raw-socket probe does not support a proxy"}
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return {"inconclusive": True, "reason": "target URL is not HTTP(S)"}
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = parsed.scheme == "https"

    try:
        control = _probe(host, port, "a-b", use_tls, timeout)
        trigger = _probe(host, port, "a\nb", use_tls, timeout)
    except ImportError:
        return {
            "inconclusive": True,
            "reason": "the optional 'h2' package is not installed (pip install 'proofcms[http2]')",
        }
    except (OSError, ssl.SSLError) as exc:
        return {
            "inconclusive": True,
            "reason": f"the HTTP/2 probe could not connect ({type(exc).__name__}: {exc})",
        }
    evidence = {
        "host": host,
        "port": port,
        "control": control,
        "trigger": trigger,
    }
    if not control["accepted"]:
        return {**evidence, "inconclusive": True, "reason": "the valid-trailer control was not accepted"}
    if trigger["rejected"]:
        return {**evidence, "vulnerable": False, "patched": True}
    if trigger["accepted"]:
        return {**evidence, "vulnerable": True, "patched": False}
    return {**evidence, "inconclusive": True, "reason": "no clear response for the newline trailer"}


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aspnet_runtime: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Finding:
    del cms_version, kwargs
    runtime = aspnet_runtime or {}
    gate = core_runtime_gate(
        cve=CVE_ID,
        name=NAME,
        rule=RULE,
        component="ASP.NET Core / Kestrel",
        vulnerability_type="HTTP Request Smuggling",
        aspnet_runtime=runtime,
        exploit_available=HAS_EXPLOIT,
    )
    if gate is not None:
        return gate
    version = runtime.get("version")
    status = classify_version(version)

    if status == Status.PATCHED:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=status,
            confidence=Confidence.HIGH,
            component="ASP.NET Core / Kestrel",
            component_version=version,
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            detail=f"ASP.NET Core {version} is at or beyond the fixed release for this branch.",
            action="No action is required for this CVE if the runtime version is accurate.",
        )

    if not run_exploit_check:
        detail = (
            f"ASP.NET Core {version} is in the affected range. The public issue is a Kestrel "
            "HTTP/2 trailer/HPACK newline acceptance; the safe differential is available with "
            "--run-exploit and --exploit-mode safe."
        )
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=status,
            confidence=Confidence.HIGH if version else Confidence.MEDIUM,
            component="ASP.NET Core / Kestrel",
            component_version=version,
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            detail=detail,
            action=FIXED_RULE,
        )

    if exploit_mode != "safe":
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.BLOCKED_EXTERNAL,
            confidence=Confidence.MEDIUM,
            component="ASP.NET Core / Kestrel",
            component_version=version,
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            detail="Only the safe trailer differential is implemented; no smuggled request is sent.",
            action="Use --exploit-mode safe against the isolated lab.",
        )

    probe = run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    if probe.get("inconclusive"):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.LIKELY_VULNERABLE if status == Status.LIKELY_VULNERABLE else Status.INCONCLUSIVE,
            confidence=Confidence.MEDIUM,
            component="ASP.NET Core / Kestrel",
            component_version=version,
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=target_url,
            evidence=probe,
            detail=f"The safe differential was inconclusive: {probe.get('reason', 'no clear result')}.",
            action=FIXED_RULE,
        )
    if probe.get("vulnerable"):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.VULNERABLE,
            confidence=Confidence.CONFIRMED,
            component="ASP.NET Core / Kestrel",
            component_version=version,
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=target_url,
            evidence=probe,
            detail=(
                "The valid trailer was accepted, and the trailer containing a newline was also "
                "accepted with a 200 response. Patched Kestrel rejects the newline trailer with "
                "RST_STREAM/GOAWAY or 400."
            ),
            action=FIXED_RULE,
        )
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=Status.PATCHED,
        confidence=Confidence.CONFIRMED,
        component="ASP.NET Core / Kestrel",
        component_version=version,
        affected_rule=RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=True,
        proof_url=target_url,
        evidence=probe,
        detail="The valid trailer was accepted, but the newline trailer was rejected with a GOAWAY PROTOCOL_ERROR.",
        action="No action is required for this CVE.",
    )


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


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
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "vulnerability_type": "HTTP Request Smuggling",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-19",
        "updated": "2026-11-19",
        "required_detectors": ["aspnet"],
        "references": [
            "https://github.com/dotnet/aspnetcore/discussions/69798",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-70188",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-70188",
        ],
    }
