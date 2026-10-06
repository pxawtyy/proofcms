from __future__ import annotations

import html
import re
import secrets
import urllib.parse
from typing import Any

from ...core.http import HttpSession, normalize_url

MEDIA_FORM_PATH = "/index.php?option=com_media&view=images&tmpl=component"


def _attrs(tag: str) -> dict[str, str]:
    return {
        key.lower(): html.unescape(value)
        for key, _, value in re.findall(r"([\w:-]+)\s*=\s*(['\"])(.*?)\2", tag, re.DOTALL)
    }


def discover_media_form(
    session: HttpSession, response: dict[str, Any] | None = None
) -> dict[str, Any] | None:
    response = response or session.get(MEDIA_FORM_PATH)
    if response.get("status") != 200 or response.get("redirected"):
        return None
    body = response.get("body", "")
    for block in re.findall(r"<form\b.*?</form>", body, re.IGNORECASE | re.DOTALL):
        opening = re.search(r"<form\b[^>]*>", block, re.IGNORECASE | re.DOTALL)
        if not opening:
            continue
        form_attrs = _attrs(opening.group(0))
        action = form_attrs.get("action", "")
        if "com_media" not in action or "file.upload" not in action:
            continue
        file_name = None
        fields: dict[str, str] = {}
        for tag in re.findall(r"<input\b[^>]*>", block, re.IGNORECASE | re.DOTALL):
            attrs = _attrs(tag)
            name = attrs.get("name")
            if not name:
                continue
            if attrs.get("type", "").lower() == "file":
                file_name = name
            elif attrs.get("type", "").lower() in {"hidden", ""}:
                fields[name] = attrs.get("value", "")
        if file_name:
            return {
                "action": urllib.parse.urljoin(response.get("final_url") or session.base_url or "", action),
                "file_field": file_name,
                "fields": fields,
                "source": response.get("final_url") or MEDIA_FORM_PATH,
            }
    return None


def probe_media_upload(
    target_url: str,
    *,
    filename: str,
    payload: bytes,
    marker: str,
    content_type: str,
    timeout: int = 12,
    proxy: str | None = None,
) -> dict[str, Any]:
    base = normalize_url(target_url)
    session = HttpSession(base_url=base, timeout=timeout, proxy=proxy)
    surface = session.get(MEDIA_FORM_PATH)
    form = discover_media_form(session, surface)
    if not form:
        status = surface.get("status", 0)
        state = "denied" if status in {401, 403} else "redirected" if surface.get("redirected") else "absent"
        return {
            "surface_found": state in {"denied", "redirected"},
            "surface_state": state,
            "surface_status": status,
            "accepted": False,
            "attempts": [f"media upload surface {state} (HTTP {status})"],
        }

    upload = session.post(
        form["action"],
        fields=form["fields"],
        files={form["file_field"]: (filename, payload, content_type)},
    )
    proof_path = f"/images/{urllib.parse.quote(filename)}"
    proof = session.get(proof_path)
    missing = session.get(f"/images/proofcms-missing-{secrets.token_hex(8)}.txt")
    verified = (
        proof.get("status") == 200
        and marker in proof.get("body", "")
        and proof.get("body_hash") != missing.get("body_hash")
        and not proof.get("redirected")
    )
    return {
        "surface_found": True,
        "surface_state": "form_exposed",
        "surface_status": 200,
        "accepted": verified,
        "write_reported": upload.get("status") in {200, 201, 202, 204, 301, 302, 303},
        "upload_status": upload.get("status", 0),
        "upload_redirected": upload.get("redirected", False),
        "proof_status": proof.get("status", 0),
        "proof_body": proof.get("body", "") if verified else "",
        "proof_url": f"{base}{proof_path}",
        "uploaded_filename": f"images/{filename}" if verified else None,
        "file_field": form["file_field"],
        "form_source": form["source"],
        "attempts": [
            (
                f"form={form['source']},field={form['file_field']},upload={upload.get('status', 0)},"
                f"proof={proof.get('status', 0)},marker={verified}"
            )
        ],
    }
