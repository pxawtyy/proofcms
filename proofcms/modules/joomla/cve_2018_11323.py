from __future__ import annotations

import re
from typing import Any

from ...core.args import aggressive_value
from ...core.auth import joomla_admin_login
from ...core.http import HttpClient, normalize_url
from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_required, parse_version_safe
from .advisory import passive_core_finding

CVE_ID = "CVE-2018-11323"
NAME = "Joomla core ACL violation in access levels"
AFFECTED_RULE = "Joomla 2.5.0 through 3.8.7 (access levels of higher-permission groups)"
REMEDIATION = "Upgrade to Joomla 3.8.8 or a newer supported release and review user group access levels."
EDIT_PATH = "/administrator/index.php?option=com_users&task=level.edit&id={id}"
VULN_TYPE = "Improper Access Control"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return Status.DETECTED_VERSION_UNKNOWN
    if parsed < parse_version_required("2.5.0"):
        return Status.NOT_AFFECTED
    return Status.LIKELY_VULNERABLE if parsed < parse_version_required("3.8.8") else Status.PATCHED


def _denied(body: str) -> bool:
    return bool(
        re.search(
            r"Edit not permitted|not permitted to use that link", body, re.IGNORECASE
        )
    )


def _form_opened(body: str) -> bool:
    return "Edit Viewing Access Level" in body


def run_safe_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    aggressive_command: str | None = None,
) -> Finding:
    """Read-only differential on the access-level edit form.

    Needs a delegated users-component admin (core.admin on com_users, but not
    a global Super User) and a viewing access level whose first group is a
    Super User group. A baseline level whose first group is not a Super User
    must open on both builds; that controls for an account that cannot reach
    the form at all. Affected 3.8.7 renders the edit form for the protected
    level; fixed 3.8.8 denies it. No data is read back or changed.
    """
    base = normalize_url(target_url)
    user = aggressive_value(aggressive_args, aggressive_command, "admin_user")
    password = aggressive_value(aggressive_args, aggressive_command, "admin_password")
    level_id = aggressive_value(aggressive_args, aggressive_command, "viewlevel_id")
    baseline_id = (
        aggressive_value(aggressive_args, aggressive_command, "baseline_viewlevel_id", "1") or "1"
    )

    evidence: dict[str, Any] = {
        "viewlevel_id": level_id,
        "baseline_viewlevel_id": baseline_id,
        "credentials_supplied": bool(user and password),
    }
    if not user or not password or not level_id:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_CONFIRMED,
            confidence=Confidence.MEDIUM,
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=False,
            proof_url=f"{base}{EDIT_PATH.format(id=level_id or '')}",
            evidence=evidence,
            detail=(
                "The read-only access-level probe needs --aggressive-arg admin_user=..., "
                "admin_password=... and viewlevel_id=<level whose first group is a Super User group>."
            ),
            action=REMEDIATION,
            vulnerability_type=VULN_TYPE,
        )

    client = HttpClient(base_url=base, timeout=timeout, proxy=proxy)
    logged_in = joomla_admin_login(
        client, "", user, password, timeout=timeout, strict_status=False
    )
    evidence["login_ok"] = logged_in
    if not logged_in:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_CONFIRMED,
            confidence=Confidence.MEDIUM,
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{EDIT_PATH.format(id=level_id)}",
            evidence=evidence,
            detail="The supplied users-component admin account could not reach the administrator area.",
            action=REMEDIATION,
            vulnerability_type=VULN_TYPE,
        )

    baseline_path = EDIT_PATH.format(id=baseline_id)
    target_path = EDIT_PATH.format(id=level_id)
    baseline = client.get(baseline_path, timeout=timeout)
    target = client.get(target_path, timeout=timeout)
    baseline_body = str(baseline.get("body", ""))
    target_body = str(target.get("body", ""))
    baseline_opened = _form_opened(baseline_body)
    target_opened = _form_opened(target_body)
    target_denied = _denied(target_body)
    evidence.update(
        {
            "baseline_status": baseline.get("status", 0),
            "baseline_form_opened": baseline_opened,
            "baseline_denied": _denied(baseline_body),
            "target_status": target.get("status", 0),
            "target_form_opened": target_opened,
            "target_denied": target_denied,
        }
    )

    if not baseline_opened:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_CONFIRMED,
            confidence=Confidence.MEDIUM,
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{target_path}",
            evidence=evidence,
            detail=(
                "The baseline access-level edit form did not open for the supplied account, "
                "so it lacks the required component-level authorization (test inconclusive)."
            ),
            action=REMEDIATION,
            vulnerability_type=VULN_TYPE,
        )

    if target_opened and not target_denied:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.VULNERABLE,
            confidence=Confidence.CONFIRMED,
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{target_path}",
            evidence=evidence,
            detail=(
                "The delegated users-component admin could open the edit form for a viewing "
                "access level whose first group is a Super User group, while a baseline level "
                "opened as expected. The fixed release denies this edit. No data was changed."
            ),
            action=REMEDIATION,
            vulnerability_type=VULN_TYPE,
        )

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=Status.NOT_CONFIRMED,
        confidence=Confidence.MEDIUM,
        component="Joomla core",
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=f"{base}{target_path}",
        evidence=evidence,
        detail=(
            "The protected access level's edit form was denied (or did not render) for the "
            "delegated admin while the baseline level opened, consistent with the fixed guard."
        ),
        action=REMEDIATION,
        vulnerability_type=VULN_TYPE,
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
    result = passive_core_finding(
        cve=CVE_ID,
        name=NAME,
        affected_rule=AFFECTED_RULE,
        joomla_version=joomla_version,
        classify=classify_version,
        remediation=REMEDIATION,
    )
    result.vulnerability_type = VULN_TYPE
    if not run_exploit_check:
        return result
    if exploit_mode != "safe":
        result.detail += " This module supports only the read-only safe access-level probe."
        return result
    if result.status not in {Status.LIKELY_VULNERABLE, Status.INCONCLUSIVE}:
        result.detail += " Safe proof skipped because the detected Joomla release is not affected."
        return result
    probe = run_safe_probe(
        target_url,
        timeout=timeout,
        proxy=proxy,
        aggressive_args=aggressive_args,
        aggressive_command=aggressive_command,
    )
    probe.component_version = joomla_version
    return probe


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": "Joomla core",
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": ["2.5.0-3.8.7"],
        "exploit_available": True,
        "exploit_modes": ["safe"],
        "intrusive": False,
        "vulnerability_type": VULN_TYPE,
        "module_version": "2.0.0",
        "last_reviewed": "2026-11-22",
        "updated": "2026-11-22",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2018-11323",
            "https://developer.joomla.org/security-centre/729-20180501-core-acl-violation-in-access-levels.html",
        ],
    }
