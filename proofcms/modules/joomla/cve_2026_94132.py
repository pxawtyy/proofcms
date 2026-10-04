from __future__ import annotations

from typing import Any

from ...core.http import HttpClient, normalize_url
from ...core.probes import rand_str
from .acymailing_advisory import acymailing_finding, metadata_base

CVE_ID = "CVE-2026-94132"
NAME = "AcyMailing Enterprise mailbox attachment RCE"
AFFECTED_RULE = "AcyMailing Enterprise 1.0.0 through 11.0.5; fixed in 11.1.0"


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> dict[str, Any]:
    client = HttpClient(normalize_url(target_url), timeout=timeout, proxy=proxy)
    directory = client.get("/media/com_acym/upload/", timeout=timeout)
    missing_name = f"proofcms-missing-{rand_str(12)}/"
    missing = client.get(f"/media/com_acym/{missing_name}", timeout=timeout)
    body = directory.get("body", "")
    listing = directory.get("status") == 200 and any(
        marker in body.lower() for marker in ("index of", "parent directory", "directory listing")
    )
    distinct = bool(directory.get("body_hash") and directory.get("body_hash") != missing.get("body_hash"))
    return {
        "upload_path": "/media/com_acym/upload/",
        "directory_status": directory.get("status", 0),
        "missing_control_status": missing.get("status", 0),
        "missing_control_path": f"/media/com_acym/{missing_name}",
        "directory_listing": listing,
        "distinct_from_missing_control": distinct,
    }


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    plugins: dict | None = None,
    **kwargs: Any,
):
    finding = acymailing_finding(
        cve=CVE_ID,
        name=NAME,
        affected_rule=AFFECTED_RULE,
        fixed_version="11.1.0",
        plugins=plugins,
        enterprise_only=True,
        remediation=(
            "Upgrade AcyMailing Enterprise to 11.1.0 or newer and inspect media/com_acym/upload/ for executable files."
        ),
    )
    finding.exploit_available = True
    if not run_exploit_check or finding.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        return finding
    if exploit_mode != "safe":
        finding.detail += " This module supports a read-only safe companion probe."
        return finding
    proof = run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    finding.exploit_ran = True
    finding.evidence = {**(finding.evidence or {}), **proof}
    finding.detail += (
        " Read-only companion probe checked media/com_acym/upload/ against a random missing-file control. "
        f"Directory status={proof['directory_status']}; listing={proof['directory_listing']}. The mailbox CVE "
        "requires out-of-band delivery to the configured POP3 inbox, so no attachment was sent and RCE is not claimed."
    )
    return finding


def metadata() -> dict[str, Any]:
    data = metadata_base(
        cve=CVE_ID,
        name=NAME,
        affected_rule=AFFECTED_RULE,
        enterprise_only=True,
        references=["https://www.cve.org/CVERecord?id=CVE-2026-94132"],
    )
    data.update({"exploit_available": True, "exploit_modes": ["safe"], "module_version": "1.1.0"})
    return data
