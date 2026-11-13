from __future__ import annotations

import socket
import ssl
import urllib.parse
from typing import Any

from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2025-55315"
NAME = "ASP.NET Core Kestrel chunk-extension request smuggling"
RULE = "ASP.NET Core 2.3 before 2.3.6, 8.0 before 8.0.21, 9.0 before 9.0.10, and .NET 10 before 10.0.0-rc2"
FIXED_RULE = "Upgrade ASP.NET Core to 2.3.6, 8.0.21, 9.0.10, 10.0.0-rc2, or newer"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]

# A valid chunked body used as the keep-alive control.
_VALID_CHUNK = b"2;foo=bar\r\nxy\r\n0\r\n\r\n"
# The CVE trigger: a lone LF inside the chunk extension.
_CVE_CHUNK = b"2;\n\r\nxy\r\n0\r\n\r\n"
# A generic invalid chunk size; both vulnerable and patched reject it.
_BAD_SIZE_CHUNK = b"Z\r\nxy\r\n0\r\n\r\n"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return Status.DETECTED_VERSION_UNKNOWN
    if parse_version_required("2.3.0") <= parsed < parse_version_required("2.3.6"):
        return Status.LIKELY_VULNERABLE
    if parse_version_required("8.0.0") <= parsed < parse_version_required("8.0.21"):
        return Status.LIKELY_VULNERABLE
    if parse_version_required("9.0.0") <= parsed < parse_version_required("9.0.10"):
        return Status.LIKELY_VULNERABLE
    if version and version.lower().startswith("10.0.0-rc1"):
        return Status.LIKELY_VULNERABLE
    return Status.PATCHED


def _status_line(data: bytes) -> str:
    return data.split(b"\r\n", 1)[0].decode(errors="replace") if data else ""


def _send_chunk(host: str, port: int, chunk: bytes, timeout: int, use_tls: bool) -> dict[str, Any]:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        request = (
            b"GET / HTTP/1.1\r\n"
            b"Host: " + host.encode() + b"\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: keep-alive\r\n"
            b"\r\n"
            + chunk
        )
        sock.sendall(request)
        sock.settimeout(timeout)
        data = b""
        closed = False
        try:
            while True:
                part = sock.recv(4096)
                if not part:
                    closed = True
                    break
                data += part
        except TimeoutError:
            closed = False
        sock.close()
        return {"closed": closed, "status": _status_line(data), "bytes": len(data)}
    except OSError as exc:
        return {"closed": True, "status": "", "bytes": 0, "error": f"{type(exc).__name__}: {exc}"}


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(target_url)
    if proxy:
        return {"inconclusive": True, "reason": "raw-socket probe does not support a proxy"}
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return {"inconclusive": True, "reason": "target URL is not HTTP(S)"}
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = parsed.scheme == "https"

    valid = _send_chunk(host, port, _VALID_CHUNK, timeout, use_tls)
    cve = _send_chunk(host, port, _CVE_CHUNK, timeout, use_tls)
    bad_size = _send_chunk(host, port, _BAD_SIZE_CHUNK, timeout, use_tls)

    evidence = {
        "valid": valid,
        "cve": cve,
        "bad_size": bad_size,
        "host": host,
        "port": port,
    }
    if valid.get("closed") or not bad_size.get("closed"):
        return {**evidence, "inconclusive": True, "reason": "server connection behavior is not suitable for the differential"}
    if cve.get("closed"):
        return {**evidence, "vulnerable": False, "patched": True}
    return {**evidence, "vulnerable": True, "patched": False}


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    **kwargs: Any,
) -> Finding:
    del kwargs
    status = classify_version(cms_version)
    if status == Status.PATCHED:
        return Finding(
            cve=CVE_ID, name=NAME, status=status, confidence=Confidence.HIGH,
            component="ASP.NET Core / Kestrel", component_version=cms_version,
            affected_rule=RULE, exploit_available=HAS_EXPLOIT,
            detail=f"ASP.NET Core {cms_version} is at or beyond the fixed release.",
            action=FIXED_RULE,
            vulnerability_type="HTTP Request Smuggling",
        )
    if not run_exploit_check:
        confidence = Confidence.HIGH if status == Status.LIKELY_VULNERABLE else Confidence.MEDIUM
        detail = (
            f"ASP.NET Core {cms_version} is in the affected range."
            if status == Status.LIKELY_VULNERABLE
            else "ASP.NET Core was detected, but its exact runtime version is unknown."
        )
        return Finding(
            cve=CVE_ID, name=NAME, status=status, confidence=confidence,
            component="ASP.NET Core / Kestrel", component_version=cms_version,
            affected_rule=RULE, exploit_available=HAS_EXPLOIT,
            detail=detail, action=FIXED_RULE,
            vulnerability_type="HTTP Request Smuggling",
        )
    if exploit_mode != "safe":
        return Finding(
            cve=CVE_ID, name=NAME, status=status, confidence=Confidence.MEDIUM,
            component="ASP.NET Core / Kestrel", component_version=cms_version,
            affected_rule=RULE, exploit_available=HAS_EXPLOIT,
            detail="This module supports only the safe chunk-extension differential.",
            action=FIXED_RULE, vulnerability_type="HTTP Request Smuggling",
        )

    probe = run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    if probe.get("vulnerable"):
        return Finding(
            cve=CVE_ID, name=NAME, status=Status.VULNERABLE, confidence=Confidence.CONFIRMED,
            component="ASP.NET Core / Kestrel", component_version=cms_version,
            affected_rule=RULE, exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=target_url, evidence=probe,
            detail=(
                "Kestrel kept the connection open for a chunk extension containing a lone LF while "
                "closing it for a generic invalid chunk size, the pre-patch parsing behavior behind "
                "CVE-2025-55315. No smuggled request was sent."
            ),
            action=FIXED_RULE, vulnerability_type="HTTP Request Smuggling",
        )
    if probe.get("patched"):
        return Finding(
            cve=CVE_ID, name=NAME, status=Status.PATCHED, confidence=Confidence.HIGH,
            component="ASP.NET Core / Kestrel", component_version=cms_version,
            affected_rule=RULE, exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=target_url, evidence=probe,
            detail="Kestrel closed the connection for the lone-LF chunk extension, the patched behavior.",
            action=FIXED_RULE, vulnerability_type="HTTP Request Smuggling",
        )
    return Finding(
        cve=CVE_ID, name=NAME, status=Status.INCONCLUSIVE, confidence=Confidence.MEDIUM,
        component="ASP.NET Core / Kestrel", component_version=cms_version,
        affected_rule=RULE, exploit_available=HAS_EXPLOIT, exploit_ran=True,
        proof_url=target_url, evidence=probe,
        detail=f"The safe differential was inconclusive: {probe.get('reason', 'unexpected connection behavior')}.",
        action=FIXED_RULE, vulnerability_type="HTTP Request Smuggling",
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
        "affected_versions": [">=2.3.0,<2.3.6", ">=8.0.0,<8.0.21", ">=9.0.0,<9.0.10", "10.0.0-rc1"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "vulnerability_type": "HTTP Request Smuggling",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-13",
        "updated": "2026-11-13",
        "required_detectors": ["aspnet"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2025-55315",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-55315",
            "https://andrewlock.net/understanding-the-worst-dotnet-vulnerability-request-smuggling-and-cve-2025-55315/",
            "https://gist.github.com/N3mes1s/d0897c13ca199e739ecc2b562f466040",
        ],
    }
