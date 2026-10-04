from __future__ import annotations

import secrets
from typing import Any

from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_required, parse_version_safe
from .elfinder import cleanup, discover, endpoint_url, first_added, read_file, upload

CVE_ID = "CVE-2021-23394"
RULE = "elFinder before 2.1.58"


def classify_version(version: str | None) -> str:
    value = parse_version_safe(version)
    if value is None:
        return Status.DETECTED_VERSION_UNKNOWN
    return Status.LIKELY_VULNERABLE if value < parse_version_required("2.1.58") else Status.PATCHED


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False,
          timeout: int = 12, proxy: str | None = None, **kwargs: Any) -> Finding:
    conn = discover(target_url, timeout, proxy)
    if not conn:
        return Finding(CVE_ID, "elFinder PHAR upload filter bypass", Status.NOT_DETECTED, Confidence.MEDIUM,
                       "Web library elFinder", affected_rule=RULE, exploit_available=True,
                       detail="No public elFinder connector was detected at standard paths.",
                       action="Verify manually if elFinder uses a custom connector path.")
    status = classify_version(conn.get("version"))
    result = Finding(CVE_ID, "elFinder PHAR upload filter bypass", status,
                     Confidence.HIGH if conn.get("version") else Confidence.MEDIUM, "Web library elFinder",
                     conn.get("version"), RULE, True, detail="A public elFinder connector was detected.",
                     action="Upgrade elFinder to 2.1.58 or newer and restrict connector access.",
                     proof_url=endpoint_url(target_url, conn))
    if not run_exploit_check or status == Status.PATCHED:
        return result
    marker = f"PROOFCMS_SAFE_{secrets.token_hex(8)}"
    filename = f"proofcms_{secrets.token_hex(5)}.phar"
    response = upload(conn, filename, marker.encode(), "text/plain")
    added = first_added(response, filename)
    result.exploit_ran = True
    if added and marker in read_file(conn, added["hash"]):
        result.status, result.confidence = Status.VULNERABLE_UPLOAD_ONLY, Confidence.CONFIRMED
        result.detail = "The anonymous connector accepted and returned an inert .phar file, confirming the missing PHAR MIME denial. No PHP code was uploaded or executed."
        cleanup(conn, [added["hash"]])
    else:
        result.status, result.confidence = Status.NOT_CONFIRMED, Confidence.MEDIUM
        result.detail = "The public connector was found, but the inert .phar upload was rejected or could not be read back."
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "generic", "name": "elFinder PHAR upload filter bypass",
            "component": "Web library elFinder", "affected_rule": RULE, "affected_versions": ["<2.1.58"],
            "exploit_available": True, "exploit_modes": ["safe"], "intrusive": False,
            "references": ["https://github.com/Studio-42/elFinder/commit/75ea92decc16a5daf7f618f85dc621d1b534b5e1", "https://nvd.nist.gov/vuln/detail/CVE-2021-23394"]}
