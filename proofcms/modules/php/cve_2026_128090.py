from __future__ import annotations

import re
from typing import Any

from ...core.categories import VulnerabilityType
from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Confidence, Finding, Status
from ...core.transcript import attach_transcript
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2026-128090"
NAME = "PHAR OpenSSL signature bypass via algorithm downgrade"
RULE = (
    "PHP <8.2.36, 8.3.* <8.3.37, 8.4.* <8.4.28, 8.5.* <8.5.13 "
    "(OpenSSL-signed phar with a trusted .pubkey)"
)
TYPE = VulnerabilityType.CODE_EXECUTION
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


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return Status.DETECTED_VERSION_UNKNOWN
    branch = f"{parsed.major}.{parsed.minor}"
    fixed = FIXED_BY_BRANCH.get(branch)
    if fixed:
        return Status.LIKELY_VULNERABLE if parsed < parse_version_required(fixed) else Status.PATCHED
    if branch in LEGACY_BRANCHES or parsed.major < 8 or (parsed.major == 8 and parsed.minor < 2):
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
                "Upgrade to 8.2.36, 8.3.37, 8.4.28, or 8.5.13; verify the phar "
                "signature type out-of-band and keep phar files out of attacker-writable paths."
            ),
            vulnerability_type=TYPE,
        )

    status = classify_version(version)
    if status == Status.LIKELY_VULNERABLE:
        detail = (
            f"Detected PHP {version}; the version is in the advisory range. The bypass "
            "needs an OpenSSL-signed phar, a trusted .pubkey file, and write access to "
            "the phar (but not the .pubkey). The attacker switches the stored signature "
            "type to a keyless hash such as SHA-256 and recomputes the digest; "
            "phar.require_hash=1 does not stop it. Native, tar-based and zip-based "
            "phars are affected. The tampered archive can execute attacker code when "
            "the application loads it."
        )
        confidence = Confidence.MEDIUM
    elif status == Status.PATCHED:
        detail = f"Detected PHP {version}, which is at or beyond the branch-specific fixed release."
        confidence = Confidence.HIGH
    elif status == Status.NOT_CONFIRMED:
        detail = (
            f"Detected PHP {version} on an EOL branch without an upstream fixed release. "
            "The effective status depends on the distributor package and any backported fix."
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
            "Upgrade to 8.2.36, 8.3.37, 8.4.28, or 8.5.13; verify the phar "
            "signature type out-of-band and keep phar files out of attacker-writable paths."
        ),
        evidence={
            "source": runtime.get("source"),
            "server": runtime.get("server"),
            "active_probe": "not_sent",
            "requires": "OpenSSL-signed phar + trusted .pubkey + write access to the phar",
            "package_backport_required": status == Status.NOT_CONFIRMED,
        },
        vulnerability_type=TYPE,
    )


def run_aggressive_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    """Load the lab's downgraded phar and check whether the code executes.

    The lab builds an OpenSSL-signed phar, downgrades the stored signature
    type to SHA-256 with a recomputed digest, keeps the trusted .pubkey, and
    opens the tampered archive. Affected builds accept it and execute the
    archive's main.php; fixed builds reject the keyless signature.
    """
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    response = client.get(f"{base}/index.php", timeout=max(timeout, 30))
    body = str(response.get("body", ""))
    status = int(response.get("status", 0) or 0)
    lab_php = _powered_by(response)
    bypass = "BYPASS" in body and "PWNED" in body
    rejected = "REJECTED" in body and "signature does not use openssl" in body

    evidence = attach_transcript(
        {
            "endpoint": "/index.php",
            "lab_php": lab_php,
            "status": status,
            "bypass": bypass,
            "rejected": rejected,
            "body": body[:400],
            "transport_error": is_transport_error(response),
        },
        client,
    )

    if is_transport_error(response):
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
            detail=f"The lab request failed in transit ({transport_error_detail(response)}).",
            action="Retry when the target is reachable.",
            evidence=evidence,
            vulnerability_type=TYPE,
        )

    if bypass:
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
                "The OpenSSL-signed phar was downgraded to a keyless SHA-256 signature "
                "while the trusted .pubkey was still present. The tampered archive "
                "passed verification and its main.php executed. Fixed builds reject "
                "the keyless signature. This confirms CVE-2026-128090."
            ),
            action=(
                "Upgrade to 8.2.36, 8.3.37, 8.4.28, or 8.5.13; verify the phar "
                "signature type out-of-band and keep phar files out of attacker-writable paths."
            ),
            evidence=evidence,
            vulnerability_type=TYPE,
        )

    if rejected:
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
                "The downgraded archive was rejected with 'openssl public key found, "
                "but the signature does not use openssl'; this is the fixed-build behavior."
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
            f"The lab endpoint returned HTTP {status} without the bypass or rejection "
            "marker; the phar/OpenSSL geometry may differ from the expected lab."
        ),
        action="Confirm the lab uses phar.readonly=0, phar.require_hash=1, and the test key files.",
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
            " This CVE needs the lab-only phar signature-downgrade differential "
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
            "https://nvd.nist.gov/vuln/detail/CVE-2026-128090",
            "https://github.com/php/php-src/commit/db90b7ba0db7f6568c61c4eb1c4c22968bfab575",
            "https://www.php.net/",
        ],
    }
