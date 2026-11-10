from __future__ import annotations

from typing import Any

from ...core.models import Finding
from ...core.versions import parse_version_safe, version_lt
from .k2_upload_probe import probe_inert_extension

COMPONENT = "K2"


def check_k2_dangerous_extension(
    *,
    cve: str,
    name: str,
    extension: str,
    fixed_version: str = "2.28",
    target_url: str,
    plugins: dict[str, Any] | None,
    run_exploit_check: bool,
    exploit_mode: str,
    timeout: int,
    proxy: str | None,
    aggressive_command: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
) -> Finding:
    k2 = (plugins or {}).get("k2", {})
    version = k2.get("version")
    affected_rule = (
        f"K2 releases before {fixed_version} (Verot class.upload .{extension} "
        "dangerous-file bypass: the 2019/2024 library renames are defeated by "
        "K2's file_new_name_ext override until the handler deny-list)"
    )
    base = {
        "cve": cve,
        "name": name,
        "component": COMPONENT,
        "component_version": version,
        "affected_rule": affected_rule,
        "exploit_available": True,
    }
    if not k2.get("found"):
        return Finding(
            **base,
            status="NOT_DETECTED",
            confidence="MEDIUM",
            detail="K2 was not detected through its public manifest or routes.",
            action="Verify manually if K2 is installed under a non-standard path.",
        )
    parsed_version = parse_version_safe(version)
    if version and parsed_version is None:
        return Finding(
            **base,
            status="INCONCLUSIVE",
            confidence="MEDIUM",
            detail=f"K2 was detected, but version value {version!r} could not be parsed.",
            action=f"Manually verify K2 and upgrade to {fixed_version} or newer if needed.",
        )
    if parsed_version is not None and not version_lt(version, fixed_version):
        return Finding(
            **base,
            status="PATCHED",
            confidence="HIGH",
            detail=f"K2 {version} includes the attachment handler deny-list blocking .{extension} uploads.",
            action=f"Keep K2 at {fixed_version} or newer.",
        )

    result = Finding(
        **base,
        status="LIKELY_VULNERABLE" if parsed_version is not None else "INCONCLUSIVE",
        confidence="HIGH" if parsed_version is not None else "MEDIUM",
        detail=(
            f"Detected K2 {version}, which bundles the affected upload library. "
            "Exploitation additionally requires a K2 item-creation upload surface and sufficient author permissions."
            if version
            else "K2 was detected, but its version could not be classified."
        ),
        action=f"Upgrade K2 to {fixed_version} or newer and inspect media/k2/attachments for .{extension} files.",
    )
    if not run_exploit_check:
        return result
    if exploit_mode != "aggressive":
        result.detail += (
            " The inert attachment PoC is available only in aggressive mode because it creates an unpublished K2 item."
        )
        return result

    admin_user = admin_pass = None
    if aggressive_args and aggressive_args.get("admin_user"):
        admin_user = str(aggressive_args["admin_user"])
        admin_pass = str(aggressive_args.get("admin_password", ""))
    elif aggressive_command and ":" in aggressive_command:
        admin_user, admin_pass = aggressive_command.split(":", 1)

    proof = probe_inert_extension(
        target_url,
        extension,
        timeout=timeout,
        proxy=proxy,
        admin_user=admin_user,
        admin_pass=admin_pass,
    )
    result.exploit_ran = True
    if proof.get("accepted"):
        via = "backend" if proof.get("form_path", "").startswith("/administrator") else "frontend"
        result.status = "VULNERABLE_UPLOAD_ONLY"
        result.confidence = "CONFIRMED"
        result.proof_url = proof["proof_url"]
        result.uploaded_filename = proof["filename"]
        result.detail = (
            f"K2 accepted an inert .{extension} attachment through its {via} item-save flow and returned the exact "
            f"unique marker from {proof['proof_url']}. No executable code was uploaded."
        )
        result.action = (
            f"Delete {proof['filename']} and its unpublished ProofCMS K2 item, then upgrade K2 to "
            f"{fixed_version} or newer."
        )
        return result
    if not proof.get("form_found"):
        reason = proof.get("reason", "")
        result.status = "NOT_CONFIRMED"
        result.confidence = "MEDIUM"
        result.detail = (
            f"K2 {version or 'version unknown'} is affected by version, but no usable item-save attachment surface "
            f"was reached.{' ' + reason + '.' if reason else ''} The CVE requires a K2 item-creation upload surface; "
            "supply administrator credentials via --aggressive-arg admin_user=<u> --aggressive-arg admin_password=<p> "
            "(or --aggressive-command user:pass)."
        )
        return result

    upload = proof.get("upload", {})
    result.status = "NOT_CONFIRMED"
    result.confidence = "MEDIUM"
    result.detail = (
        f"The K2 item form was reached, but the inert .{extension} attachment was not retrievable with its unique "
        f"marker. Upload status: {upload.get('status', 0)}; redirected={upload.get('redirected', False)}."
    )
    return result
