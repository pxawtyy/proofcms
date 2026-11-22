from __future__ import annotations

import re
from typing import Any

from ...core.categories import VulnerabilityType
from ...core.http import HttpSession, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Confidence, Finding, Status
from ...core.transcript import attach_transcript
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2026-126714"
NAME = "PHP files session handler partial-overwrite session corruption"
RULE = (
    "PHP <8.2.36, 8.3.* <8.3.37, 8.4.* <8.4.28, 8.5.* <8.5.13 "
    "(session.save_handler=files)"
)
TYPE = VulnerabilityType.OBJECT_INJECTION
HAS_EXPLOIT = True
EXPLOIT_MODES = ["aggressive"]

FIXED_BY_BRANCH = {
    "8.2": "8.2.36",
    "8.3": "8.3.37",
    "8.4": "8.4.28",
    "8.5": "8.5.13",
}
LEGACY_BRANCHES = {"7.4", "8.0", "8.1"}
POWERED_BY_RE = re.compile(r"PHP/([0-9]+(?:\.[0-9]+)+)", re.IGNORECASE)
OLD_WRITTEN = "OLD_WRITTEN"
OLD_PRESENT = "OLD_SUFFIX_PRESENT"
OLD_ABSENT = "OLD_SUFFIX_ABSENT"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return Status.DETECTED_VERSION_UNKNOWN
    branch = f"{parsed.major}.{parsed.minor}"
    fixed = FIXED_BY_BRANCH.get(branch)
    if fixed:
        return Status.LIKELY_VULNERABLE if parsed < parse_version_required(fixed) else Status.PATCHED
    if branch in LEGACY_BRANCHES or parsed.major < 8 or (parsed.major == 8 and parsed.minor < 2):
        # The advisory lists every version below 8.2.36, but the official EOL
        # mitigation branches disable session upload progress. A public
        # version string cannot distinguish a mitigated/backported build.
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
                "Upgrade to 8.2.36, 8.3.37, 8.4.28, or 8.5.13; as a temporary "
                "measure disable session.upload_progress.enabled and limit "
                "untrusted data stored in sessions."
            ),
            vulnerability_type=TYPE,
        )

    status = classify_version(version)
    if status == Status.LIKELY_VULNERABLE:
        detail = (
            f"Detected PHP {version}; the version is in the advisory range for the "
            "files session handler. Exploitation needs attacker influence over session "
            "data (for example session upload progress or application-stored strings), "
            "an interrupted replacement write that leaves the old suffix, and a "
            "deserialization gadget chain in the application."
        )
        confidence = Confidence.MEDIUM
    elif status == Status.PATCHED:
        detail = f"Detected PHP {version}, which is at or beyond the branch-specific fixed release."
        confidence = Confidence.HIGH
    elif status == Status.NOT_CONFIRMED:
        detail = (
            f"Detected PHP {version} on an EOL branch without an upstream fixed release. "
            "The official EOL mitigation branches disable session upload progress; "
            "verify the distributor package and the effective configuration."
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
            "Upgrade to 8.2.36, 8.3.37, 8.4.28, or 8.5.13; as a temporary measure "
            "disable session.upload_progress.enabled and limit untrusted data stored "
            "in sessions. Use an atomic session backend if the upgrade cannot be deployed."
        ),
        evidence={
            "source": runtime.get("source"),
            "server": runtime.get("server"),
            "active_probe": "not_sent",
            "session_handler": "files (default)",
            "package_backport_required": status == Status.NOT_CONFIRMED,
        },
        vulnerability_type=TYPE,
    )


def run_aggressive_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    """Run the lab's phase-1/phase-2 session-file differential.

    Phase 1 writes a normal session file. Phase 2 performs a larger session
    write while an LD_PRELOAD helper short-writes the file; affected builds
    keep the old suffix (OLD_SUFFIX_PRESENT), fixed builds truncate first
    (OLD_SUFFIX_ABSENT). The probe does not deserialize an object or execute
    code; it demonstrates the root-cause write defect.
    """
    base = normalize_url(target_url)
    sess = HttpSession(base, timeout=timeout, proxy=proxy)

    baseline = sess.get("/index.php", timeout=timeout)
    baseline_body = str(baseline.get("body", ""))
    if baseline.get("status") != 200 or OLD_WRITTEN not in baseline_body:
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
                "The lab baseline endpoint /index.php did not answer with the expected "
                "OLD_WRITTEN marker. The session-file differential needs the "
                "labs/cve-2026-126714 app; no probe was sent."
            ),
            action="Serve the labs/cve-2026-126714 app and retry in an isolated lab.",
            evidence={"baseline_status": baseline.get("status")},
            vulnerability_type=TYPE,
        )

    lab_php = _powered_by(baseline)
    probe = sess.get("/index.php?phase=2", timeout=max(timeout, 30))
    probe_body = str(probe.get("body", ""))
    probe_status = int(probe.get("status", 0) or 0)
    present = OLD_PRESENT in probe_body
    absent = OLD_ABSENT in probe_body

    evidence = attach_transcript(
        {
            "endpoint": "/index.php?phase=2",
            "lab_php": lab_php,
            "baseline_status": baseline.get("status"),
            "probe_status": probe_status,
            "old_suffix_present": present,
            "old_suffix_absent": absent,
            "probe_transport_error": is_transport_error(probe),
        },
        sess,
    )

    if is_transport_error(probe):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.ERROR,
            confidence=Confidence.LOW,
            component="PHP runtime",
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=f"{base}/index.php?phase=2",
            detail=f"The phase-2 request failed in transit ({transport_error_detail(probe)}).",
            action="Restart the lab stack and retry; confirm /index.php answers 200 first.",
            evidence=evidence,
            vulnerability_type=TYPE,
        )

    if present:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.VULNERABLE,
            confidence=Confidence.CONFIRMED,
            component="PHP runtime",
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=f"{base}/index.php?phase=2",
            detail=(
                "After the short replacement write, the session file still contained the "
                "old suffix (OLD_SUFFIX_PRESENT). Fixed builds truncate the session file "
                "before writing and lose the suffix. This confirms the CVE-2026-126714 "
                "file-write defect without deserializing an object or executing code."
            ),
            action=(
                "Upgrade to 8.2.36, 8.3.37, 8.4.28, or 8.5.13; as a temporary measure "
                "disable session.upload_progress.enabled and limit untrusted data stored "
                "in sessions."
            ),
            evidence=evidence,
            vulnerability_type=TYPE,
        )

    if absent:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_CONFIRMED,
            confidence=Confidence.HIGH,
            component="PHP runtime",
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=f"{base}/index.php?phase=2",
            detail=(
                "The short replacement write left only the new prefix "
                "(OLD_SUFFIX_ABSENT), which is the fixed-build behavior."
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
        proof_url=f"{base}/index.php?phase=2",
        detail=(
            f"The phase-2 request returned HTTP {probe_status} without either session "
            "marker; the lab geometry may differ from the expected files-handler path."
        ),
        action="Confirm the lab uses session.save_handler=files and the short-write helper.",
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
            " This CVE needs the lab-only session-file differential (aggressive mode)."
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
            "https://nvd.nist.gov/vuln/detail/CVE-2026-126714",
            "https://github.com/php/php-src/security/advisories/GHSA-fm2m-fjf5-v3cp",
            "https://github.com/php/php-src/commit/e2d3cee9ad4b0b739f4a8ebe6a69c938399b7da6",
            "https://depthfirst.com/phpaftershell",
            "https://www.php.net/",
        ],
    }
