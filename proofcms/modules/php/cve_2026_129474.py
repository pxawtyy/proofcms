from __future__ import annotations

import re
from typing import Any

from ...core.categories import VulnerabilityType
from ...core.http import HttpSession, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Confidence, Finding, Status
from ...core.transcript import attach_transcript
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2026-129474"
NAME = "PHP magic method backtrace use-after-free"
RULE = (
    "PHP 8.5.0 through 8.5.12; fixed in 8.5.13 "
    "(requires fatal_error_backtraces=1 and zend.exception_ignore_args=0)"
)
TYPE = VulnerabilityType.MEMORY_CORRUPTION
HAS_EXPLOIT = True
EXPLOIT_MODES = ["aggressive"]
FIXED = "8.5.13"

FIXED_BACKTRACE_RE = re.compile(r"C::test\(\s*1,\s*2,\s*3,\s*4,\s*'a", re.IGNORECASE)
STALE_BACKTRACE_RE = re.compile(r"C::test\(\s*3,\s*4,", re.IGNORECASE)
NULL_ARGS_RE = re.compile(r"NULL,\s*NULL")
BACKTRACE_LINE_RE = re.compile(r"#0 [^\n]*C::test\([^\n]*")
LAB_PHP_RE = re.compile(r"PHP=([0-9]+(?:\.[0-9]+)+)")


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return Status.DETECTED_VERSION_UNKNOWN
    if parsed.major != 8 or parsed.minor != 5:
        return Status.NOT_AFFECTED
    return Status.LIKELY_VULNERABLE if parsed < parse_version_required(FIXED) else Status.PATCHED


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
            action="Upgrade PHP to 8.5.13; as a workaround set zend.exception_ignore_args=1 or fatal_error_backtraces=0.",
            vulnerability_type=TYPE,
        )

    status = classify_version(version)
    if status == Status.LIKELY_VULNERABLE:
        detail = (
            f"Detected PHP {version}; fatal error backtraces are enabled by default in 8.5. "
            "Exploitation also needs zend.exception_ignore_args=0 and a reachable "
            "__call()/__callStatic() path that hits a fatal error. php.ini-production "
            "sets zend.exception_ignore_args=1 and blocks this path."
        )
        confidence = Confidence.MEDIUM
    elif status == Status.PATCHED:
        detail = f"Detected PHP {version}, which includes the 8.5.13 backtrace fix."
        confidence = Confidence.HIGH
    elif status == Status.NOT_AFFECTED:
        detail = (
            f"Detected PHP {version}; the advisory's remote attack path is limited to "
            "PHP 8.5 before 8.5.13."
        )
        confidence = Confidence.HIGH
    else:
        detail = "PHP was detected, but its version could not be determined from public HTTP responses."
        confidence = Confidence.LOW

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
            "Upgrade PHP to 8.5.13; as a workaround set zend.exception_ignore_args=1 "
            "or fatal_error_backtraces=0 and restart the workers."
        ),
        evidence={
            "source": runtime.get("source"),
            "server": runtime.get("server"),
            "active_probe": "not_sent",
            "required_ini": "fatal_error_backtraces=1,zend.exception_ignore_args=0",
        },
        vulnerability_type=TYPE,
    )


def _backtrace_line(body: str) -> str:
    match = BACKTRACE_LINE_RE.search(body)
    return match.group(0).strip() if match else ""


def run_aggressive_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    """Trigger the upstream GHSA-8mjj-2r7p-4hg2 fatal-backtrace differential.

    Lab-only: the request only causes a memory_limit fatal in the lab app.
    Affected builds print stale trampoline arguments (for example
    ``C::test(3, 4, ..., NULL, NULL)``); fixed builds print the real
    ``C::test(1, 2, 3, 4, ...)`` arguments. Nothing executes either way.
    """
    base = normalize_url(target_url)
    sess = HttpSession(base, timeout=timeout, proxy=proxy)

    baseline = sess.get("/index.php", timeout=timeout)
    baseline_body = str(baseline.get("body", ""))
    if baseline.get("status") != 200 or "OK" not in baseline_body:
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
                "The lab baseline endpoint /index.php did not answer with the expected OK marker. "
                "The fatal-backtrace differential needs the labs/cve-2026-129474 app; no payload was sent."
            ),
            action="Serve the labs/cve-2026-129474 app and retry in an isolated lab.",
            evidence={"baseline_status": baseline.get("status")},
            vulnerability_type=TYPE,
        )

    lab_php_match = LAB_PHP_RE.search(baseline_body)
    lab_php = lab_php_match.group(1) if lab_php_match else None

    response = sess.get("/index.php?probe=1", timeout=max(timeout, 30))
    body = str(response.get("body", ""))
    fatal = "Allowed memory size" in body and "Stack trace" in body
    fixed = bool(FIXED_BACKTRACE_RE.search(body))
    stale = bool(STALE_BACKTRACE_RE.search(body) or NULL_ARGS_RE.search(body))
    line = _backtrace_line(body)

    evidence = attach_transcript(
        {
            "endpoint": "/index.php?probe=1",
            "lab_php": lab_php,
            "probe_status": response.get("status"),
            "fatal_memory_text": fatal,
            "fixed_backtrace": fixed,
            "stale_backtrace": stale,
            "backtrace_line": line,
        },
        sess,
    )

    if is_transport_error(response):
        after = sess.get("/index.php", timeout=timeout)
        alive = after.get("status") == 200 and "OK" in str(after.get("body", ""))
        if alive:
            return Finding(
                cve=CVE_ID,
                name=NAME,
                status=Status.VULNERABLE,
                confidence=Confidence.CONFIRMED,
                component="PHP runtime",
                affected_rule=RULE,
                exploit_available=HAS_EXPLOIT,
                exploit_ran=True,
                proof_url=f"{base}/index.php?probe=1",
                detail=(
                    "The fatal-backtrace request killed the lab worker while the benign "
                    "control still answered 200. Fixed builds return a clean fatal instead."
                ),
                action=(
                    "Upgrade PHP to 8.5.13; as a workaround set zend.exception_ignore_args=1 "
                    "or fatal_error_backtraces=0."
                ),
                evidence=evidence,
                vulnerability_type=TYPE,
            )
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.ERROR,
            confidence=Confidence.LOW,
            component="PHP runtime",
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=f"{base}/index.php?probe=1",
            detail=(
                "The fatal-backtrace request failed in transit and the benign control also "
                f"failed ({transport_error_detail(response)}); the lab worker may be down."
            ),
            action="Restart the lab stack and retry; confirm /index.php answers 200 first.",
            evidence=evidence,
            vulnerability_type=TYPE,
        )

    if fatal and stale and not fixed:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.VULNERABLE,
            confidence=Confidence.CONFIRMED,
            component="PHP runtime",
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=f"{base}/index.php?probe=1",
            detail=(
                "The fatal-error backtrace for the __callStatic trampoline exposed stale "
                f"arguments ({line}) instead of C::test(1, 2, 3, 4, ...). Fixed builds "
                "print the real arguments. This confirms CVE-2026-129474 without executing code."
            ),
            action=(
                "Upgrade PHP to 8.5.13; as a workaround set zend.exception_ignore_args=1 "
                "or fatal_error_backtraces=0."
            ),
            evidence=evidence,
            vulnerability_type=TYPE,
        )

    if fatal and fixed:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_CONFIRMED,
            confidence=Confidence.HIGH,
            component="PHP runtime",
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=f"{base}/index.php?probe=1",
            detail=(
                "The fatal-error backtrace contains the real C::test(1, 2, 3, 4, ...) "
                "arguments, which is the fixed-build behavior."
            ),
            action="No action required if the runtime is at or beyond PHP 8.5.13.",
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
        proof_url=f"{base}/index.php?probe=1",
        detail=(
            "The probe endpoint answered but did not produce the expected memory_limit "
            f"fatal or trampoline backtrace (status {response.get('status')})."
        ),
        action="Confirm the lab php.ini geometry (memory_limit=4M, fatal_error_backtraces=1, zend.exception_ignore_args=0).",
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
            " This CVE needs the lab-only fatal-backtrace differential (aggressive mode)."
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
        "affected_versions": [">=8.5.0,<8.5.13"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": True,
        "vulnerability_type": TYPE,
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-22",
        "updated": "2026-11-22",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-129474",
            "https://github.com/php/php-src/security/advisories/GHSA-8mjj-2r7p-4hg2",
            "https://github.com/php/php-src/commit/9300a6f7ae4d4be14d66111fd88fca9d81e34491",
            "https://www.php.net/",
        ],
    }
