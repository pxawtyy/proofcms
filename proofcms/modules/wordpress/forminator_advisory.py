from __future__ import annotations

import json
import re
from typing import Any

from ...core.http import normalize_url, request
from ...core.models import Finding
from ...core.versions import parse_version_safe

PLUGIN_SLUG = "forminator"
COMPONENT = "WordPress plugin Forminator"


def classify_version(version: str | None, *, minimum: str | None = None, fixed: str) -> str:
    parsed = parse_version_safe(version)
    fixed_version = parse_version_safe(fixed)
    minimum_version = parse_version_safe(minimum) if minimum else None
    if parsed is None or fixed_version is None:
        return "DETECTED_VERSION_UNKNOWN"
    if minimum_version is not None and parsed < minimum_version:
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if parsed < fixed_version else "PATCHED"


def passive_result(
    *,
    cve: str,
    name: str,
    affected_rule: str,
    plugins: dict[str, Any] | None,
    fixed: str,
    minimum: str | None = None,
    remediation: str,
    vulnerability_type: str | None = None,
) -> Finding:
    plugin = (plugins or {}).get(PLUGIN_SLUG, {})
    if not isinstance(plugin, dict) or not plugin.get("found"):
        return Finding(
            cve=cve,
            name=name,
            status="NOT_DETECTED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=affected_rule,
            exploit_available=True,
            detail="Forminator was not detected in public WordPress assets or metadata.",
            action=f"No action is required unless Forminator is installed but hidden from public detection. {remediation}",
            vulnerability_type=vulnerability_type or "",
        )
    version = plugin.get("version")
    status = classify_version(version, minimum=minimum, fixed=fixed)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected Forminator {version}, which is within the published affected range."
        confidence = "HIGH" if plugin.get("version_confidence", "HIGH") == "HIGH" else "MEDIUM"
        action = remediation
    elif status == "PATCHED":
        detail = f"Detected Forminator {version}, which includes the published fix."
        confidence = "HIGH"
        action = "No action is required for this CVE if version detection is accurate."
    elif status == "NOT_AFFECTED":
        detail = f"Detected Forminator {version}, outside the published affected range."
        confidence = "HIGH"
        action = "No action is required for this CVE if version detection is accurate."
    else:
        detail = "Forminator was detected, but its version could not be determined."
        confidence = "MEDIUM"
        action = remediation
    return Finding(
        cve=cve,
        name=name,
        status=status,
        confidence=confidence,
        component=COMPONENT,
        component_version=version,
        affected_rule=affected_rule,
        exploit_available=True,
        detail=detail,
        action=action,
        vulnerability_type=vulnerability_type or "",
    )


def candidate_pages(target_url: str, timeout: int, proxy: str | None) -> list[str]:
    target = normalize_url(target_url)
    pages = [f"{target}/"]
    response = request(
        f"{target}/?rest_route=/wp/v2/pages&per_page=50&_fields=link",
        timeout=timeout,
        proxy=proxy,
    )
    if response.get("status") == 200:
        try:
            payload = json.loads(response.get("body", ""))
        except (TypeError, json.JSONDecodeError):
            payload = []
        if isinstance(payload, list):
            pages.extend(item["link"] for item in payload if isinstance(item, dict) and isinstance(item.get("link"), str))
    return list(dict.fromkeys(pages))


def discover_forms(target_url: str, timeout: int, proxy: str | None) -> list[dict[str, Any]]:
    forms: list[dict[str, Any]] = []
    for page_url in candidate_pages(target_url, timeout, proxy):
        response = request(page_url, timeout=timeout, proxy=proxy)
        if response.get("status") != 200:
            continue
        body = str(response.get("body", ""))
        if "forminator" not in body.lower():
            continue
        ids = set(re.findall(r"(?:data-form-id|data-forminator-render|forminator-form-)(?:=|[\"']?\s*[:=]\s*)[\"']?(\d+)", body, re.IGNORECASE))
        has_quiz = bool(re.search(r"forminator[_-](?:quiz|quizzes)|forminator-quiz", body, re.IGNORECASE))
        has_upload = bool(re.search(r"<input[^>]+type=[\"']file[\"']", body, re.IGNORECASE))
        has_select = bool(re.search(r"<select\b", body, re.IGNORECASE))
        nonce = next(iter(re.findall(r"(?:nonce|_wpnonce)[\"']?\s*[:=]\s*[\"']([^\"']+)", body, re.IGNORECASE)), None)
        forms.append({"page_url": page_url, "form_ids": sorted(ids), "has_quiz": has_quiz, "has_upload": has_upload, "has_select": has_select, "nonce": nonce})
    return forms


def blocked_finding(*, cve: str, name: str, affected_rule: str, detail: str, action: str) -> Finding:
    return Finding(
        cve=cve,
        name=name,
        status="BLOCKED_EXTERNAL",
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=affected_rule,
        exploit_available=True,
        exploit_ran=True,
        detail=detail,
        action=action,
    )
