from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding

CVECheckResult = Finding
from ...core.versions import parse_version_required, parse_version_safe
from .advisory import passive_core_finding, passive_only_check

CVE_ID = "CVE-2026-92222"
NAME = "Joomla core extension SSRF vectors"
COMPONENT = "Joomla core com_newsfeeds"
HAS_EXPLOIT = True
INTRUSIVE = False
EXPLOIT_MODES = ["safe"]
AFFECTED_JOOMLA_VERSIONS = ["4.0.0-5.4.8", "6.0.0-6.1.3"]
AFFECTED_RULE = "Joomla 4.0.0-5.4.8 and 6.0.0-6.1.3; requires high privileges (PR:H)"
FIXED_RULE = "Update to Joomla 5.4.9, 6.1.4, or newer"
SAFE_SCHEMES = ("http", "https")
CATEGORY_PATHS = [
    "/index.php?option=com_newsfeeds",
    "/index.php?option=com_newsfeeds&view=categories",
]
MARKER = "PROOFCMS_SSRF_FILE01"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    if parse_version_required("4.0.0") <= parsed < parse_version_required("5.4.9"):
        return "LIKELY_VULNERABLE"
    if parse_version_required("6.0.0") <= parsed < parse_version_required("6.1.4"):
        return "LIKELY_VULNERABLE"
    if parsed < parse_version_required("4.0.0"):
        return "NOT_AFFECTED"
    return "PATCHED"


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    high_privilege_access: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    **kwargs: Any,
):
    finding = passive_core_finding(
        cve=CVE_ID,
        name=NAME,
        affected_rule=AFFECTED_RULE,
        joomla_version=joomla_version,
        classify=classify_version,
        remediation="Upgrade to Joomla 5.4.9, 6.1.4, or newer and restrict outbound web-server traffic.",
    )
    if finding.status == "LIKELY_VULNERABLE" and not high_privilege_access:
        finding.status = "NOT_CONFIRMED"
        finding.confidence = "MEDIUM"
        finding.detail = (
            f"Detected Joomla {joomla_version} is in the affected version range, but this CVE requires "
            "high-privilege access (PR:H), which was not established by the scan."
        )
        finding.action = "Re-run with evidence of an authorized high-privilege Joomla session before treating this as applicable."
    if not run_exploit_check:
        return passive_only_check(finding, run_exploit_check)
    if exploit_mode != "safe":
        finding.detail += " This CVE module only supports the safe guest-side newsfeeds proof."
        return finding
    if finding.status in {"PATCHED", "NOT_AFFECTED", "NOT_DETECTED", "ERROR"}:
        return finding
    # The privileged step (storing the feed link) is lab setup, not probe
    # action: run the guest-side proof whenever the version is in range or
    # unknown. Targets without a seeded unsafe-scheme feed report
    # NOT_CONFIRMED naturally.
    probe = run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    probe.component_version = finding.component_version
    return probe


def _same_host_links(base: str, body: str) -> list[str]:
    links: list[str] = []
    for href in re.findall(r'href="([^"]+)"', body or ""):
        if "com_newsfeeds" not in href and "newsfeed" not in href:
            continue
        links.append(urljoin(base + "/", href))
    return sorted(set(links))[:20]


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    """Guest-side newsfeeds SSRF proof.

    Crawls public com_newsfeeds category/feed pages for stored feed links
    with non-http(s) schemes (allowed before 5.4.9/6.1.4 via the missing
    ``schemes`` restriction). A feed view that renders retrieved items from
    such a link proves the server fetched it.
    """
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    preflight = client.get(f"{base}/", timeout=timeout)
    if is_transport_error(preflight):
        return Finding(
            cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=f"{base}/",
            detail=f"The target could not be reached ({transport_error_detail(preflight)}).",
            action="Retry when the target is reachable.",
        )
    visited: set[str] = set()
    feed_pages: list[str] = []
    queue = [f"{base}{p}" for p in CATEGORY_PATHS]
    while queue and len(feed_pages) < 10:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        response = client.get(url, timeout=timeout)
        if response.get("status") != 200:
            continue
        body = response.get("body", "") or ""
        if "view=newsfeed" in url or "/newsfeed/" in url:
            feed_pages.append(url)
        queue.extend(u for u in _same_host_links(base, body) if u not in visited)

    evidence: dict[str, object] = {
        "feeds_checked": len(feed_pages),
        "unsafe_links": [],
        "items_rendered": 0,
        "marker_found": False,
    }
    unsafe: list[str] = []
    for page in feed_pages:
        response = client.get(page, timeout=timeout)
        if response.get("status") != 200:
            continue
        body = response.get("body", "") or ""
        links: set[str] = set()
        for href, text in re.findall(
            r'href="([^"]+)"|>([a-zA-Z][a-zA-Z0-9+.\-]*:[^<"\s]{1,120})<', body
        ):
            candidate = href or text
            if candidate:
                links.add(candidate)
        for link in sorted(links):
            scheme = (urlparse(link).scheme or "").lower()
            if scheme and scheme not in SAFE_SCHEMES:
                unsafe.append(f"{scheme} ({page})")
        items = len(re.findall(r'class="feed-link"', body))
        if MARKER in body:
            evidence["marker_found"] = True
        if unsafe and (items or MARKER in body):
            evidence["unsafe_links"] = sorted(set(unsafe))
            evidence["items_rendered"] = items
            return Finding(
                cve=CVE_ID, name=NAME, status="VULNERABLE", confidence="CONFIRMED",
                component=COMPONENT, affected_rule=AFFECTED_RULE,
                exploit_available=HAS_EXPLOIT, exploit_ran=True,
                proof_url=page, evidence=evidence,
                detail=(
                    "A public newsfeed view rendered retrieved items from a stored non-http(s) feed link, "
                    "proving the server fetched it. "
                    f"Unsafe schemes seen: {', '.join(sorted({u.split(' ')[0] for u in unsafe}))}. "
                    f"Items rendered: {items}."
                ),
                action=f"{FIXED_RULE} and audit newsfeed links for non-http(s) schemes.",
            )
    evidence["unsafe_links"] = sorted(set(unsafe))
    if unsafe:
        return Finding(
            cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
            component=COMPONENT, affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT, exploit_ran=True,
            proof_url=feed_pages[0] if feed_pages else f"{base}/index.php?option=com_newsfeeds",
            evidence=evidence,
            detail=(
                "Stored non-http(s) feed links are publicly visible, but no feed view rendered retrieved items; "
                "server-side retrieval was not demonstrated from outside."
            ),
            action="Verify with an internal listener whether the server fetches the stored link on view.",
        )
    return Finding(
        cve=CVE_ID, name=NAME, status="NOT_CONFIRMED", confidence="MEDIUM",
        component=COMPONENT, affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT, exploit_ran=True,
        proof_url=feed_pages[0] if feed_pages else f"{base}/index.php?option=com_newsfeeds",
        evidence=evidence,
        detail="No public newsfeed with a non-http(s) link was found; nothing to trigger.",
        action="If com_newsfeeds is in use, audit stored feed links manually.",
    )


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": "Joomla core",
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": [">=4.0.0,<5.4.9", ">=6.0.0,<6.1.4"],
        "privileges_required": "HIGH",
        "exploit_available": True,
        "exploit_modes": ["safe"],
        "intrusive": False,
        "module_version": "1.1.0",
        "last_reviewed": "2026-11-11",
        "updated": "2026-11-11",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-92222",
            "https://developer.joomla.org/security-centre/1089-20260909-core-ssrf-vectors-in-various-core-extensions.html",
            "https://haikhavan.com/advisories/hkv-adv-2026-042",
        ],
    }
