from __future__ import annotations

import re
import secrets
from typing import Any
from urllib.parse import quote

from ...core.http import is_transport_error, normalize_url, request, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-102426"
NAME = "SP Page Builder Dynamic Content Filter reflected XSS"
COMPONENT = "SP Page Builder"
AFFECTED_RULE = (
    "SP Page Builder Pro 5.6.0-6.0.0 Dynamic Content Filter; "
    "6.1.0-6.9.x unconfirmed; fixed in 6.10.0 (CNA lists 3.0.0-5.6.1p2)"
)
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]
DCF_INTRODUCED = "5.6.0"
DCF_FIRST_FIXED_ADVISORY = "6.0.0"
DCF_FIX_CONFIRMED = "6.10.0"
SLIDER_FIELD_RE = re.compile(r'class="slider-(?:min|max)-value"[^>]*data-field-id="(\d+)"')


def classify_version(version: str | None) -> str:
    if version and str(version).strip().lower() == "5.6.1p2":
        return "LIKELY_VULNERABLE"
    parsed = parse_version_safe(version)
    if parsed is None:
        return "DETECTED_VERSION_UNKNOWN"
    introduced = parse_version_safe(DCF_INTRODUCED)
    advisory_fixed = parse_version_safe(DCF_FIRST_FIXED_ADVISORY)
    confirmed_fixed = parse_version_safe(DCF_FIX_CONFIRMED)
    if introduced is None or advisory_fixed is None or confirmed_fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    if parsed < introduced:
        # The Dynamic Content Filter addon did not exist before 5.6.0; the
        # 3.8.x branch has no dc_filter surface at all.
        return "NOT_AFFECTED"
    if parsed < advisory_fixed:
        return "LIKELY_VULNERABLE"
    if parsed < confirmed_fixed:
        # The advisory says 6.0.0 fixed it, but the 6.0.0 package still
        # prints the slider values unescaped; 6.10.0 escapes them. A vendor
        # in-place rebuild of 6.0.0 cannot be distinguished by version alone.
        return "INCONCLUSIVE"
    return "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("sppagebuilder", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="SP Page Builder was not detected.", action="No action is required unless SP Page Builder is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected SP Page Builder {version}, which carries the Dynamic Content Filter addon in the affected 5.6.0-6.0.0 range."
        action = "Upgrade SP Page Builder Pro to 6.10.0 or later and review pages that use the Dynamic Content Filter."
        confidence = "HIGH"
    elif status == "INCONCLUSIVE":
        detail = f"Detected SP Page Builder {version}. The public record says 6.0.0 fixed the filter, but the 6.0.0 package still prints the slider values unescaped and 6.10.0 escapes them; 6.1.0-6.9.x cannot be resolved from the version alone."
        action = "Upgrade to 6.10.0 or later (or the vendor's current 6.x release) and verify the Dynamic Content Filter output."
        confidence = "MEDIUM"
    elif status == "NOT_AFFECTED":
        detail = f"Detected SP Page Builder {version}, outside the Dynamic Content Filter affected range."
        action = "No action is required for this CVE when version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "SP Page Builder was detected, but its version could not be determined."
        action = "Determine the installed SP Page Builder version and upgrade to 6.10.0 or later."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def _discover_slider_field(body: str) -> str | None:
    match = SLIDER_FIELD_RE.search(body or "")
    return match.group(1) if match else None


def _raw_slider_marker(body: str, marker: str, field_id: str) -> bool:
    """True when the raw marker is the text content of the matching slider span.

    The vulnerable 6.0.0 markup puts the same unescaped value in both
    ``data-value`` and the span text, so the attribute contains ``>`` and a
    naive attribute regex breaks. Check the text node and its local window
    instead.
    """
    needle = f"<b>{marker}</b>"
    start = body.find(needle)
    while start >= 0:
        window = body[max(0, start - 800):start + len(needle) + 80]
        if f'data-field-id="{field_id}"' in window and (
            "slider-min-value" in window or "slider-max-value" in window
        ):
            return True
        start = body.find(needle, start + 1)
    return False


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    """Reflect an inert HTML marker through the DCF slider parameter.

    The probe first requires the target page to render a Dynamic Content
    Filter slider (the addon did not exist before 5.6.0). It then sends
    ``dc_filter_<fieldId>=<b>marker</b>l-r0`` and only confirms when the raw
    marker appears inside the slider span. No script payload is sent.
    """
    base = normalize_url(target_url)
    page = request(base, timeout=timeout, proxy=proxy)
    if is_transport_error(page):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=base, detail=f"Safe XSS probe could not obtain an HTTP response ({transport_error_detail(page)}).", action="Retry when the target is reachable; do not interpret transport failure as evidence of patch status.")

    field_id = _discover_slider_field(str(page.get("body", "")))
    if not field_id:
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=base, detail="The target page does not render a Dynamic Content Filter slider, so the dc_filter_<fieldId> reflection surface is absent. This is expected for SP Page Builder below 5.6.0 or for pages without the addon.", action="Point the probe at a published page that uses the Dynamic Content Filter slider, or upgrade SP Page Builder.")

    marker = f"PROOFCMS_DCF_{secrets.token_hex(6)}"
    payload = quote(f"<b>{marker}</b>l-r0", safe="")
    separator = "&" if "?" in base else "?"
    url = f"{base}{separator}dc_filter_{field_id}={payload}"
    response = request(url, timeout=timeout, proxy=proxy)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, detail=f"Safe XSS probe could not obtain an HTTP response ({transport_error_detail(response)}).", action="Retry when the target is reachable; do not interpret transport failure as evidence of patch status.")

    body = str(response.get("body", ""))
    raw_slider = _raw_slider_marker(body, marker, field_id)
    if raw_slider:
        return Finding(cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, evidence={"field_id": field_id, "marker": marker, "raw_slider_marker": True}, detail="The harmless Dynamic Content Filter marker was rendered as raw HTML inside the slider span. No script payload was sent.", action="Upgrade SP Page Builder Pro to 6.10.0 or later and remove the affected filter surface from public pages.")
    return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=url, evidence={"field_id": field_id, "marker": marker, "raw_slider_marker": False}, detail="The safe Dynamic Content Filter marker was not reflected as raw HTML in the slider span; no XSS was confirmed.", action="Upgrade affected SP Page Builder Pro versions even when external proof is inconclusive.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    passive = passive_result(plugins)
    if not run_exploit_check or exploit_mode != "safe":
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "module_version": "2.0.0", "last_reviewed": "2026-11-14", "updated": "2026-11-14", "required_detectors": ["sppagebuilder"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-102426", "https://www.joomshaper.com/joomla-extensions/sp-page-builder-pro", "https://mysites.guru/vulnerabilities/CVE-2026-102426"]}
