from __future__ import annotations

from typing import Any

from ...core.probes import rand_str
from ...core.versions import parse_version_required, parse_version_safe
from .advisory import passive_core_finding
from .joomla_media_probe import probe_media_upload

CVE_ID = "CVE-2018-15882"
NAME = "Joomla InputFilter PHAR upload bypass"
AFFECTED_RULE = "Joomla before 3.8.12"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    return "LIKELY_VULNERABLE" if parsed < parse_version_required("3.8.12") else "PATCHED"


def passive_check(joomla_version: str | None):
    finding = passive_core_finding(
        cve=CVE_ID,
        name=NAME,
        affected_rule=AFFECTED_RULE,
        joomla_version=joomla_version,
        classify=classify_version,
        remediation="Upgrade Joomla to 3.8.12 or a currently supported release and inspect uploaded files.",
    )
    finding.exploit_available = True
    return finding


def build_inert_phar_stub(marker: str) -> bytes:
    """Build a non-executing image/polyglot that exercises the missing PHAR-stub filter."""
    return f"GIF89a\n{marker}\n<?php __HALT_COMPILER(); ?>\n".encode()


def probe_upload(target_url: str, timeout: int = 12, proxy: str | None = None) -> dict[str, Any]:
    marker = f"PROOFCMS_PHAR_{rand_str(12)}"
    filename = f"proofcms-{rand_str(8)}.gif"
    payload = build_inert_phar_stub(marker)
    return probe_media_upload(
        target_url,
        filename=filename,
        payload=payload,
        marker=marker,
        content_type="image/gif",
        timeout=timeout,
        proxy=proxy,
    )


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    **kwargs: Any,
):
    finding = passive_check(joomla_version)
    if not run_exploit_check or finding.status != "LIKELY_VULNERABLE":
        return finding
    if exploit_mode != "aggressive":
        finding.detail += " Active verification writes an inert file and is available only in aggressive lab mode."
        return finding

    proof = probe_upload(target_url, timeout=timeout, proxy=proxy)
    finding.exploit_ran = True
    if proof.get("accepted"):
        finding.status = "VULNERABLE_UPLOAD_ONLY"
        finding.confidence = "CONFIRMED"
        finding.proof_url = proof["proof_url"]
        finding.uploaded_filename = proof["uploaded_filename"]
        finding.detail = (
            "Legacy com_media accepted and served a GIF file containing an inert PHAR stub marker. "
            "No executable PHP or command was included."
        )
        finding.action = (
            f"Upgrade Joomla to 3.8.12 or newer and delete {proof['uploaded_filename']} from the lab."
        )
    else:
        finding.status = "NOT_CONFIRMED"
        finding.confidence = "MEDIUM"
        surface = proof.get("surface_found", False)
        finding.detail = (
            "The prepared inert PHAR-stub upload was not publicly retrievable. "
            + (
                "A live anonymous com_media upload form was found, but this payload was rejected or discarded. "
                if surface
                else "No compatible anonymous com_media upload form was exposed. "
            )
            + "The affected InputFilter may still be present. Attempts: "
            + "; ".join(proof.get("attempts", []))
        )
        finding.evidence = {
            "upload_surface_found": surface,
            "write_reported": proof.get("write_reported", False),
            "readback_verified": False,
        }
    return finding


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": "Joomla core",
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": ["<3.8.12"],
        "exploit_available": True,
        "exploit_modes": ["aggressive"],
        "intrusive": True,
        "module_version": "1.2.0",
        "last_reviewed": "2026-10-02",
        "updated": "2026-10-02",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2018-15882",
            "https://developer.joomla.org/security-centre/743-20180801-core-hardening-the-inputfilter-for-phar-stubs.html",
        ],
    }
