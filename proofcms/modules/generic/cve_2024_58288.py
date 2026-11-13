from __future__ import annotations

from typing import Any

from ...core.models import Finding
from ...detectors.genexus import detect_genexus

CVE_ID = "CVE-2024-58288"
NAME = "GeneXus Protection Server unquoted service path"
COMPONENT = "GeneXus Protection Server"
AFFECTED_RULE = "GeneXus Protection Server 9.7.2.10 on Windows"
FIXED_RULE = "Upgrade Genexus Protection Server past 9.7.2.10 and quote the protsrvservice path"
HAS_EXPLOIT = False
INTRUSIVE = False
EXPLOIT_MODES: list[str] = []


def classify_version(version: str | None) -> str:
    if version == "9.7.2.10":
        return "LIKELY_VULNERABLE"
    return "INCONCLUSIVE"


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    genexus_info: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Finding:
    del joomla_version, kwargs
    info = genexus_info or detect_genexus(target_url, timeout=timeout, proxy=proxy)
    if not info.get("detected"):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_DETECTED",
            confidence="LOW",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail="No GeneXus application markers were detected on the target.",
            action="Verify manually if GeneXus Protection Server is deployed on a Windows host.",
        )
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = (
            "The page exposes GeneXus Protection Server 9.7.2.10. The CVE is a Windows service "
            "unquoted-path local privilege escalation, not a remotely triggerable web flaw; the "
            "version match is the strongest remote signal available."
        )
        confidence = "HIGH"
        action = "Quote the protsrvservice ImagePath and upgrade past 9.7.2.10; restrict write access to the install path."
    else:
        detail = (
            "GeneXus markers were detected, but the Protection Server 9.7.2.10 build was not "
            "identified; the generated-application version is not the same as the Protection Server build."
        )
        confidence = "MEDIUM"
        action = "Confirm the Protection Server build on the Windows host and check the protsrvservice ImagePath."
    if run_exploit_check:
        detail += " This CVE is local to the Windows service; no active web proof is sent."
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence=confidence,
        component=COMPONENT,
        component_version=version,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=False,
        detail=detail,
        action=action,
        evidence={"source": info.get("source"), "evidence": info.get("evidence", [])},
        vulnerability_type="Privilege Escalation",
    )


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "generic",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_versions": ["9.7.2.10"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "vulnerability_type": "Privilege Escalation",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-13",
        "updated": "2026-11-13",
        "required_detectors": ["genexus"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2024-58288",
            "https://www.exploit-db.com/exploits/52065",
            "https://www.vulncheck.com/advisories/genexus-protection-server-unquoted-service-path-privilege-escalation",
        ],
    }
