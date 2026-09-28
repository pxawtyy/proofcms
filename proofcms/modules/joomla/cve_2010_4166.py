from __future__ import annotations

import re
from urllib.parse import urljoin

from ...core.evidence import find_sql_errors as core_find_sql_errors
from ...core.http import normalize_url, request
from ...core.models import Finding

CVECheckResult = Finding
from ...core.versions import version_in_specifier

CVE_ID = "CVE-2010-4166"
NAME = "Joomla com_weblinks filter_order SQL injection"
COMPONENT = "Joomla core com_weblinks"
PATCHED_VERSION = "1.5.22"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]
AFFECTED_JOOMLA_VERSIONS = ["1.5.x <= 1.5.21"]
AFFECTED_RULE = "Joomla 1.5.x up to and including 1.5.21"
CONTROL_PATH = "/index.php?option=com_weblinks&view=category&id=2&filter_order_Dir=asc&filter_order=title"
POC_PATHS = [
    "/index.php?option=com_weblinks&view=category&id=2&filter_order_Dir=&filter_order=%00'",
    "/index.php?option=com_weblinks&view=category&id=2&filter_order_Dir='&filter_order=asc",
]
SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"mysql_query",
    r"mysql error",
    r"sql syntax",
    r"database error",
    r"jdatabase",
    r"warning:\s*mysql",
    r"supplied argument is not a valid mysql",
    r"unknown column",
    r"order clause",
]

# Fetch function exposed for module use and test patching
fetch = request


def affects_joomla_version(joomla_version: str | None) -> bool:
    return bool(version_in_specifier(joomla_version, ">=1.5.0,<=1.5.21"))


def passive_result(joomla_version: str | None) -> Finding:
    if not joomla_version:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="INCONCLUSIVE",
            confidence="MEDIUM",
            component=COMPONENT,
            component_version=None,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail="Joomla was detected, but the core version could not be determined.",
            action="Manually verify whether Joomla is 1.5.21 or older.",
        )

    if affects_joomla_version(joomla_version):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="LIKELY_VULNERABLE",
            confidence="HIGH",
            component=COMPONENT,
            component_version=joomla_version,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail=f"Joomla {joomla_version} is in the affected range for this com_weblinks SQL injection.",
            action="Upgrade Joomla beyond 1.5.21 or apply the vendor security fix.",
        )

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="PATCHED",
        confidence="HIGH",
        component=COMPONENT,
        component_version=joomla_version,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=f"Joomla {joomla_version} is outside the affected range.",
        action="No action required for this CVE if version detection is accurate.",
    )


def find_sql_errors(body: str) -> set[str]:
    lowered = (body or "").lower()
    matches = {pattern for pattern in SQL_ERROR_PATTERNS if re.search(pattern, lowered, re.IGNORECASE)}
    matches.update(core_find_sql_errors(body))
    return matches


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url) + "/"
    control_url = urljoin(base, CONTROL_PATH.lstrip("/"))
    control_resp = fetch(control_url, timeout=timeout, proxy=proxy)
    control_errors = find_sql_errors(control_resp.get("body", ""))

    observed = []
    pre_existing_detected = False
    for path in POC_PATHS:
        proof_url = urljoin(base, path.lstrip("/"))
        response = fetch(proof_url, timeout=timeout, proxy=proxy)
        observed.append(f"{response.get('status')} {proof_url}")
        body = response.get("body", "")
        probe_errors = find_sql_errors(body)
        diff_errors = probe_errors - control_errors

        if diff_errors and response.get("status") == 200:
            return Finding(
                cve=CVE_ID,
                name=NAME,
                status="VULNERABLE",
                confidence="CONFIRMED",
                component=COMPONENT,
                component_version=None,
                affected_rule=AFFECTED_RULE,
                exploit_available=HAS_EXPLOIT,
                exploit_ran=True,
                proof_url=proof_url,
                detail=(
                    f"Differential SQL/database error was induced by probe and not present in baseline control: "
                    f"{', '.join(sorted(diff_errors))}."
                ),
                action="Upgrade Joomla beyond 1.5.21 or apply the vendor security fix.",
            )
        if probe_errors and not diff_errors:
            pre_existing_detected = True

    detail_msg = "Safe probes did not trigger differential SQL/database errors."
    if pre_existing_detected:
        detail_msg += " (Note: Database errors were observed, but they were already present on the benign control request)."
    detail_msg += f" Observed: {'; '.join(observed)}"

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="NOT_CONFIRMED",
        confidence="MEDIUM",
        component=COMPONENT,
        component_version=None,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=True,
        detail=detail_msg,
        action="If Joomla is 1.5.21 or older, still upgrade or manually verify with server-side logs.",
    )


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aggressive_command: str | None = None,
    plugins: dict | None = None,
    **kwargs,
) -> Finding:
    passive = passive_result(joomla_version)
    if run_exploit_check:
        if exploit_mode != "safe":
            passive.detail += " This CVE only supports safe GET-based verification."
            return passive
        if passive.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
            passive.detail += " Safe probe skipped because Joomla version is outside the affected range."
            return passive
        result = run_safe_probe(target_url, timeout=timeout, proxy=proxy)
        result.component_version = joomla_version
        return result
    return passive


def metadata() -> dict:
    return {
        "cve": CVE_ID,
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": AFFECTED_JOOMLA_VERSIONS,
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "module_version": "1.2.0",
        "last_reviewed": "2026-03-20",
        "updated": "2026-03-20",
        "required_detectors": [],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2010-4166",
        ],
    }
