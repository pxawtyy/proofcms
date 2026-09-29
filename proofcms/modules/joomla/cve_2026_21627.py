from __future__ import annotations

from typing import Any

from ...core.models import Finding
from ...core.versions import version_in_specifier

CVE_ID = "CVE-2026-21627"
NAME = "Novarain/Tassos Framework improper access control"
COMPONENT = "Novarain/Tassos Framework (plg_system_nrframework)"
AFFECTED_RULE = "Tassos Framework 4.10.14-6.0.37 and affected bundled product releases"
HAS_EXPLOIT = False
INTRUSIVE = False
EXPLOIT_MODES: list[str] = []

PRODUCTS: dict[str, tuple[str, str | None]] = {
    "nrframework": ("Novarain/Tassos Framework", ">=4.10.14,<=6.0.37"),
    "convertforms": ("Convert Forms", ">=3.2.12,<=5.1.0"),
    "engagebox": ("EngageBox", ">=6.0.0,<=7.1.0"),
    "google_structured_data": ("Google Structured Data", ">=5.1.7,<=6.1.0"),
    "advanced_custom_fields": ("Advanced Custom Fields", ">=2.2.0,<=3.1.0"),
    "smilepack": ("Smile Pack", ">=1.0.0,<=2.1.0"),
    "mailchimp_auto_subscribe": ("MailChimp Auto-Subscribe", None),
}


def _classify(version: str | None, specifier: str | None) -> str:
    if not version or not specifier:
        return "INCONCLUSIVE"
    affected = version_in_specifier(version, specifier)
    if affected is None:
        return "INCONCLUSIVE"
    return "LIKELY_VULNERABLE" if affected else "PATCHED"


def check(
    target_url: str,
    joomla_version: str | None = None,
    plugins: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Finding:
    detected: list[tuple[str, str | None, str]] = []
    for key, (label, specifier) in PRODUCTS.items():
        info = (plugins or {}).get(key, {})
        if info.get("found"):
            detected.append((label, info.get("version"), _classify(info.get("version"), specifier)))

    if not detected:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_DETECTED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail="Neither the Tassos Framework nor a known bundling extension was detected.",
            action="Verify plg_system_nrframework manually if Tassos extensions use non-public paths.",
        )

    direct = next((item for item in detected if item[0] == "Novarain/Tassos Framework"), None)
    evidence = "; ".join(f"{label} {version or 'version unknown'}" for label, version, _ in detected)
    statuses = {status for _, _, status in detected}
    if direct and direct[2] == "LIKELY_VULNERABLE":
        status, confidence = "LIKELY_VULNERABLE", "HIGH"
        detail = f"Detected the affected framework directly. Evidence: {evidence}."
    elif direct and direct[2] == "PATCHED":
        status, confidence = "PATCHED", "HIGH"
        detail = f"The directly detected framework version is outside the affected range. Evidence: {evidence}."
    elif "LIKELY_VULNERABLE" in statuses:
        status, confidence = "LIKELY_VULNERABLE", "HIGH"
        detail = f"Detected a product release listed as affected because it bundles the framework. Evidence: {evidence}."
    elif statuses == {"PATCHED"}:
        status, confidence = "PATCHED", "HIGH"
        detail = f"All detected product versions are outside their published affected ranges. Evidence: {evidence}."
    else:
        status, confidence = "INCONCLUSIVE", "MEDIUM"
        detail = f"A framework-bundling product was detected, but affected status could not be resolved. Evidence: {evidence}."

    component_version = direct[1] if direct else None
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence=confidence,
        component=COMPONENT,
        component_version=component_version,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=detail,
        action="Update plg_system_nrframework to 6.0.38 or newer and update every installed Tassos extension.",
    )


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
        "required_detectors": list(PRODUCTS),
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-21627",
            "https://www.tassos.gr/",
        ],
    }
