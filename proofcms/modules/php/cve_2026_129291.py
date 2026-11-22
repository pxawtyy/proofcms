from __future__ import annotations

import re
import time
from typing import Any

from ...core.categories import VulnerabilityType
from ...core.http import HttpSession, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Confidence, Finding, Status
from ...core.transcript import attach_transcript
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2026-129291"
NAME = "PHP-FPM worker stdio pipe double-close use-after-free"
RULE = (
    "PHP 8.1.20-8.1.34, 8.2.7 <8.2.36, 8.3.* <8.3.37, 8.4.* <8.4.28, "
    "8.5.* <8.5.13; PHP-FPM catch_workers_output=yes with epoll"
)
TYPE = VulnerabilityType.PRIVILEGE_ESCALATION
HAS_EXPLOIT = True
EXPLOIT_MODES = ["aggressive"]

FIXED_BY_BRANCH = {
    "8.2": "8.2.36",
    "8.3": "8.3.37",
    "8.4": "8.4.28",
    "8.5": "8.5.13",
}
POWERED_BY_RE = re.compile(r"PHP/([0-9]+(?:\.[0-9]+)+)", re.IGNORECASE)
STDERR_FAILURE = "write to stderr failed"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return Status.DETECTED_VERSION_UNKNOWN
    if parsed.major == 8 and parsed.minor == 1:
        if parse_version_required("8.1.20") <= parsed <= parse_version_required("8.1.34"):
            # 8.1 is EOL; a public version string cannot distinguish a
            # distributor backport.
            return Status.NOT_CONFIRMED
        return Status.NOT_AFFECTED
    if parsed.major != 8 or parsed.minor < 2:
        return Status.NOT_AFFECTED
    branch = f"{parsed.major}.{parsed.minor}"
    fixed = FIXED_BY_BRANCH.get(branch)
    if fixed:
        if branch == "8.2" and parsed < parse_version_required("8.2.7"):
            return Status.NOT_AFFECTED
        return Status.LIKELY_VULNERABLE if parsed < parse_version_required(fixed) else Status.PATCHED
    return Status.NOT_AFFECTED


def _powered_by(response: dict[str, Any]) -> str | None:
    headers = response.get("headers") or {}
    values: list[str] = []
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).lower() == "x-powered-by":
                values.extend(value if isinstance(value, list) else [str(value)])
    for value in values:
        match = POWERED_BY_RE.search(value)
        if match:
            return match.group(1)
    return None


def passive_result(php_runtime: dict[str, Any] | None) -> Finding:
    runtime = php_runtime or {}
    version = runtime.get("version")
    if not runtime.get("detected"):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_DETECTED,
            confidence=Confidence.LOW,
            component="PHP runtime",
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            detail="PHP was not fingerprinted from public HTTP responses.",
            action=(
                "Upgrade to the branch-specific fixed release; as a workaround set "
                "catch_workers_output=no and restart the FPM master and workers."
            ),
            vulnerability_type=TYPE,
        )

    status = classify_version(version)
    if status == Status.LIKELY_VULNERABLE:
        detail = (
            f"Detected PHP {version}; the version is in the advisory range. The "
            "demonstrated trigger needs PHP-FPM with catch_workers_output=yes and "
            "the epoll backend. catch_workers_output is off by default but enabled "
            "in the official PHP-FPM Docker images. A local attacker who can run PHP "
            "code in a worker can crash the master or execute code with its privileges "
            "(commonly root)."
        )
        confidence = Confidence.MEDIUM
    elif status == Status.PATCHED:
        detail = f"Detected PHP {version}, which is at or beyond the branch-specific fixed release."
        confidence = Confidence.HIGH
    elif status == Status.NOT_CONFIRMED:
        detail = (
            f"Detected PHP {version} in the 8.1.20-8.1.34 affected range. PHP 8.1 "
            "is EOL; the effective status depends on the distributor package and any "
            "backported fix."
        )
        confidence = Confidence.MEDIUM
    else:
        detail = (
            f"Detected PHP {version}; the advisory's affected ranges do not include this branch."
        )
        confidence = Confidence.HIGH

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence=confidence,
        component="PHP runtime",
        component_version=version,
        affected_rule=RULE,
        exploit_available=HAS_EXPLOIT,
        detail=detail,
        action=(
            "Upgrade to the branch-specific fixed release; as a workaround set "
            "catch_workers_output=no and restart the FPM master and workers."
        ),
        evidence={
            "source": runtime.get("source"),
            "server": runtime.get("server"),
            "active_probe": "not_sent",
            "requires": "PHP-FPM catch_workers_output=yes + epoll",
            "package_backport_required": status == Status.NOT_CONFIRMED,
        },
        vulnerability_type=TYPE,
    )


def run_aggressive_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    """Run the upstream gh24046 stdio-pipe double-close sequence.

    The first request writes to stderr and starts a background sleep that
    inherits the catch_workers_output pipe. pm.max_requests=1 makes the
    worker exit while the background process keeps the pipe open. After the
    postponed free, a replacement worker reuses the fd. On affected builds
    the replacement worker's stderr write fails; fixed builds return ok.
    """
    base = normalize_url(target_url)
    sess = HttpSession(base, timeout=timeout, proxy=proxy)

    first = sess.get("/index.php?bg=1", timeout=max(timeout, 30))
    first_body = str(first.get("body", ""))
    if is_transport_error(first) or int(first.get("status", 0) or 0) != 200 or "ok" not in first_body:
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
                "The lab baseline endpoint /index.php?bg=1 did not answer with ok. "
                "The FPM double-close differential needs the labs/cve-2026-129291 app; "
                "no follow-up was sent."
            ),
            action="Serve the labs/cve-2026-129291 FPM lab and retry in an isolated lab.",
            evidence={"first_status": first.get("status")},
            vulnerability_type=TYPE,
        )

    time.sleep(1.6)
    second = sess.get("/index.php", timeout=max(timeout, 30))
    second_status = int(second.get("status", 0) or 0)
    second_body = str(second.get("body", ""))
    stderr_failed = STDERR_FAILURE in second_body
    ok = second_status == 200 and "ok" in second_body and not stderr_failed
    lab_php = _powered_by(first) or _powered_by(second)

    evidence = attach_transcript(
        {
            "first_endpoint": "/index.php?bg=1",
            "second_endpoint": "/index.php",
            "lab_php": lab_php,
            "first_status": first.get("status"),
            "second_status": second_status,
            "second_body": second_body[:200],
            "stderr_write_failed": stderr_failed,
            "second_transport_error": is_transport_error(second),
        },
        sess,
    )

    if is_transport_error(second):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.ERROR,
            confidence=Confidence.LOW,
            component="PHP runtime",
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=f"{base}/index.php",
            detail=f"The follow-up request failed in transit ({transport_error_detail(second)}).",
            action="Restart the lab stack and retry; confirm /index.php?bg=1 answers ok first.",
            evidence=evidence,
            vulnerability_type=TYPE,
        )

    if stderr_failed:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.VULNERABLE,
            confidence=Confidence.CONFIRMED,
            component="PHP runtime",
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=f"{base}/index.php",
            detail=(
                "After the background process kept the old catch_workers_output pipe "
                "open and the worker exited, the replacement worker's stderr write "
                "failed. That is the fpm_child_close double-close/UAF path: the master "
                "did not remove the epoll event before closing the reused fd. Fixed "
                "builds return ok. This confirms CVE-2026-129291 without executing code."
            ),
            action=(
                "Upgrade to the branch-specific fixed release; as a workaround set "
                "catch_workers_output=no and restart the FPM master and workers."
            ),
            evidence=evidence,
            vulnerability_type=TYPE,
        )

    if ok:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_CONFIRMED,
            confidence=Confidence.HIGH,
            component="PHP runtime",
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=f"{base}/index.php",
            detail=(
                "The replacement worker wrote to stderr successfully after the background "
                "process and the worker exit; this is the fixed-build behavior."
            ),
            action="No action required if the runtime is at or beyond the branch-specific fixed release.",
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
        proof_url=f"{base}/index.php",
        detail=(
            f"The follow-up returned HTTP {second_status} without the stderr-failure "
            "or ok marker; the lab FPM geometry may differ from the upstream test."
        ),
        action="Confirm the lab uses catch_workers_output=yes, pm.max_children=1, and pm.max_requests=1.",
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
) -> Finding:
    del cms_version, aggressive_command, aggressive_args, kwargs
    passive = passive_result(php_runtime)
    if not run_exploit_check:
        return passive
    if exploit_mode != "aggressive":
        passive.detail += (
            " This CVE needs the lab-only FPM stdio double-close differential "
            "(aggressive mode)."
        )
        return passive
    if passive.status not in {Status.LIKELY_VULNERABLE, Status.DETECTED_VERSION_UNKNOWN}:
        passive.detail += " Aggressive proof skipped because the PHP version was not potentially affected."
        return passive
    result = run_aggressive_probe(target_url, timeout=timeout, proxy=proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "php",
        "name": NAME,
        "component": "PHP runtime",
        "affected_rule": RULE,
        "affected_versions": [
            ">=8.1.20,<=8.1.34",
            ">=8.2.7,<8.2.36",
            ">=8.3.0,<8.3.37",
            ">=8.4.0,<8.4.28",
            ">=8.5.0,<8.5.13",
        ],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": True,
        "vulnerability_type": TYPE,
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-22",
        "updated": "2026-11-22",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-129291",
            "https://github.com/php/php-src/commit/13c4db2987098737278ef78849bb791866021c3c",
            "https://www.php.net/",
        ],
    }
