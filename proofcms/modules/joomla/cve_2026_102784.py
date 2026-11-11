from __future__ import annotations

from typing import Any

from ...core.models import Finding
from ...core.versions import parse_version_required, parse_version_safe
from . import gridbox_common as gb

CVE_ID = "CVE-2026-102784"
NAME = "Gridbox language installation CSRF leading to package install"
COMPONENT = "Gridbox (com_gridbox)"
HAS_EXPLOIT = False
INTRUSIVE = False
EXPLOIT_MODES: list[str] = []
AFFECTED_JOOMLA_VERSIONS = ["*"]
AFFECTED_RULE = "Gridbox 2.20.2 through 2.20.3.1"
FIXED_RULE = "Gridbox 2.20.4.0 or later"


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aggressive_command: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    plugins: dict | None = None,
    **kwargs: Any,
) -> Finding:
    info = gb.gridbox_info(plugins)
    found = bool(info.get("found"))
    version = info.get("version")
    if not found:
        return Finding(
            cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM",
            component=COMPONENT, component_version=None, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail="Gridbox was not detected through its public component manifest or asset paths.",
            action="Component not detected via standard routes; verify manually if installed at another path.",
        )
    parsed = parse_version_safe(version)
    if parsed is None:
        status = "INCONCLUSIVE"
        detail = f"Gridbox was detected ({info.get('source') or 'unknown'}) but its version could not be determined."
    elif parsed < parse_version_required("2.20.2"):
        status = "NOT_AFFECTED"
        detail = f"Gridbox {version} predates the vulnerable addLanguage implementation introduced in 2.20.2."
    elif parsed < parse_version_required("2.20.4.0"):
        status = "LIKELY_VULNERABLE"
        detail = (
            "Gridbox pages.addLanguage accepted a tokenless GET and called an attacker-chosen "
            "PHP callable on an attacker-supplied package before Installer::install(); tracked "
            "passive-only because triggering the installer is not safely reversible."
        )
    else:
        status = "PATCHED"
        detail = (
            "Gridbox 2.20.4.0 requires core.tools, reads the payload from POST, base64-decodes it "
            "and requires a session token."
        )
    result = Finding(
        cve=CVE_ID, name=NAME, status=status,
        confidence="HIGH" if status in {"LIKELY_VULNERABLE", "PATCHED", "NOT_AFFECTED"} else "MEDIUM",
        component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT, detail=detail,
        action="Upgrade Gridbox to 2.20.4.0 or later and audit installed extensions and tmp files.",
    )
    if run_exploit_check:
        result.detail += (
            " This check is passive-only: the addLanguage path reaches Joomla's package installer, "
            "so no live trigger is sent."
        )
    return result


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT,
        "affected_rule": AFFECTED_RULE, "affected_joomla_versions": AFFECTED_JOOMLA_VERSIONS,
        "exploit_available": HAS_EXPLOIT, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE,
        "vulnerability_type": "Cross-Site Request Forgery (CSRF)",
        "module_version": "1.0.0", "last_reviewed": "2026-11-11", "updated": "2026-11-11",
        "required_detectors": ["gridbox"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-102784",
            "https://mysites.guru/blog/gridbox-2-20-4-0-security-fixes/",
        ],
    }
