from __future__ import annotations

from typing import Any

from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2024-40744"
NAME = "Convert Forms unrestricted file upload"
COMPONENT = "Convert Forms"
AFFECTED_RULE = "Convert Forms before 4.4.8"
PATCHED_VERSION = "4.4.8"
HAS_EXPLOIT = False
INTRUSIVE = False
EXPLOIT_MODES: list[str] = []


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    fixed = parse_version_safe(PATCHED_VERSION)
    if parsed is None or fixed is None:
        return "INCONCLUSIVE"
    return "LIKELY_VULNERABLE" if parsed < fixed else "PATCHED"


def check(
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
        detail = f"Convert Forms was detected at {plugin.get('source', 'an unknown source')}, but its version is unknown."
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
