from __future__ import annotations

import html
import re
from typing import Any

from ...core.http import HttpClient, normalize_url
from ...core.models import Finding

MODULE_ID = "PROOFCMS-K2-REGISTRATION-AVATAR"
NAME = "K2 public-registration avatar upload surface"
COMPONENT = "K2 user profile integration"
REGISTRATION_PATH = "/index.php?option=com_users&view=registration"


def _attrs(tag: str) -> dict[str, str]:
    return {
        key.lower(): html.unescape(value)
        for key, _, value in re.findall(r"([\w:-]+)\s*=\s*(['\"])(.*?)\2", tag, re.DOTALL)
    }


def discover_registration_avatar(body: str) -> dict[str, Any] | None:
    for block in re.findall(r"<form\b.*?</form>", body, re.IGNORECASE | re.DOTALL):
        opening = re.search(r"<form\b[^>]*>", block, re.IGNORECASE | re.DOTALL)
        if not opening:
            continue
        form_attrs = _attrs(opening.group(0))
        fields: dict[str, str] = {}
        file_fields: list[str] = []
        for tag in re.findall(r"<input\b[^>]*>", block, re.IGNORECASE | re.DOTALL):
            attrs = _attrs(tag)
            name = attrs.get("name")
            if not name:
                continue
            if attrs.get("type", "").lower() == "file":
                file_fields.append(name)
            else:
                fields[name] = attrs.get("value", "")
        k2_field = next((name for name in fields if name.lower() == "k2userform"), None)
        avatar_field = next((name for name in file_fields if name.lower() in {"image", "avatar"}), None)
        enctype = form_attrs.get("enctype", "").lower()
        task = next((value for name, value in fields.items() if name.lower() == "task"), "")
        if k2_field and avatar_field and "multipart/form-data" in enctype:
            return {
                "file_field": avatar_field,
                "k2_field": k2_field,
                "k2_value": fields[k2_field],
                "task": task,
                "registration_task": task == "registration.register",
                "action": form_attrs.get("action", ""),
            }
    return None


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    **kwargs: Any,
) -> Finding:
    base = normalize_url(target_url)
    response = HttpClient(base_url=base, timeout=timeout, proxy=proxy).get(REGISTRATION_PATH)
    form = None
    if response.get("status") == 200 and not response.get("redirected"):
        form = discover_registration_avatar(response.get("body", ""))
    if not form:
        state = "denied" if response.get("status") in {401, 403} else "redirected" if response.get("redirected") else "not exposed"
        return Finding(
            cve=MODULE_ID,
            name=NAME,
            status="NOT_DETECTED",
            confidence="HIGH",
            component=COMPONENT,
            component_version=(kwargs.get("plugins") or {}).get("k2", {}).get("version"),
            affected_rule="Public Joomla registration form with K2UserForm and an avatar file field",
            detail=f"A K2 registration-avatar form was {state} (HTTP {response.get('status', 0)}).",
            action="Keep self-registration and K2 profile uploads disabled unless explicitly required.",
            proof_url=f"{base}{REGISTRATION_PATH}",
            evidence={"surface_status": response.get("status", 0), "surface_state": state},
        )

    detail = (
        f"Anonymous registration exposes multipart K2 avatar field {form['file_field']!r} with "
        f"{form['k2_field']}={form['k2_value']!r}. This is a real upload surface; file persistence and "
        "server-side image re-encoding were not tested by the passive probe."
    )
    if run_exploit_check:
        detail += " No file was submitted because registration may create an account and requires aggressive workflow support."
    return Finding(
        cve=MODULE_ID,
        name=NAME,
        status="INCONCLUSIVE",
        confidence="HIGH",
        component=COMPONENT,
        component_version=(kwargs.get("plugins") or {}).get("k2", {}).get("version"),
        affected_rule="Public Joomla registration form with K2UserForm and an avatar file field",
        exploit_available=False,
        exploit_ran=False,
        detail=detail,
        action="Disable public registration or the K2 avatar field; validate image re-encoding, quotas, rate limits, and activation policy.",
        proof_url=f"{base}{REGISTRATION_PATH}",
        evidence={"registration_open": True, "avatar_upload_form": True, **form},
    )


def metadata() -> dict[str, Any]:
    return {
        "cve": MODULE_ID,
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": "Public Joomla registration form with K2UserForm and an avatar file field",
        "affected_joomla_versions": ["*"],
        "exploit_available": False,
        "exploit_modes": [],
        "intrusive": False,
        "module_version": "1.0.0",
        "last_reviewed": "2026-10-06",
        "updated": "2026-10-06",
        "required_detectors": ["k2"],
        "references": [],
    }
