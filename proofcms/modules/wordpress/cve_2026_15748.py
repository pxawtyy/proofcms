from __future__ import annotations

from typing import Any

from ...core.models import Finding
from .forminator_advisory import COMPONENT, discover_forms, passive_result

CVE_ID = "CVE-2026-15748"
NAME = "Forminator select-field injection to unrestricted file upload"
AFFECTED_RULE = "Forminator 1.18.1-1.56.1; fixed in 1.56.2"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]


def classify_version(version: str | None) -> str:
    from .forminator_advisory import classify_version as classify

    return classify(version, minimum="1.18.1", fixed="1.56.2")


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    forms = [form for form in discover_forms(target_url, timeout, proxy) if form["has_upload"] and form["has_select"]]
    if not forms:
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, detail="No public Forminator form containing both a file-upload field and a select field was found.", action="Upgrade Forminator to 1.56.2 or newer and review private forms for this field combination.")
    return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, detail="A public form has the vulnerable field combination, but no file was uploaded and no server-side mutation was attempted by the safe probe.", action="Upgrade Forminator to 1.56.2 or newer; validate with an authenticated staging-only test if proof is required.")


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    passive = passive_result(cve=CVE_ID, name=NAME, affected_rule=AFFECTED_RULE, plugins=plugins, fixed="1.56.2", minimum="1.18.1", remediation="Upgrade Forminator to 1.56.2 or newer.")
    if not run_exploit_check or exploit_mode != "safe" or passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "wordpress", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_versions": ["1.18.1-1.56.1"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "module_version": "1.0.0", "last_reviewed": "2026-10-12", "updated": "2026-10-12", "required_detectors": ["detect_wordpress_plugins"], "references": ["https://github.com/ubaydev/CVE-2026-15748", "https://aretiq.ai/research/vul260818-cve-2026-15748-wpmu-dev-forminator-forms-select-field-injection-unrestricted-file-upload/", "https://mcpsec.dev/forminator-security/"]}
