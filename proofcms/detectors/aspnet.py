from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit, urlunsplit

from ..core.http import HttpClient, normalize_url
from ..core.models import AspNetRuntimeInfo

_GENERATOR = re.compile(r'<meta[^>]+name=["\']Generator["\'][^>]+content=["\']([^"\']+)', re.IGNORECASE)
_VERSION_META = re.compile(r'<meta[^>]+name=["\']Version["\'][^>]+content=["\']([^"\']+)', re.IGNORECASE)
_GENERATOR_COMMENT = re.compile(r"GeneXus\s+([A-Za-z0-9+#.-]+)\s+Generator\s+version\s+([\w.-]+)", re.IGNORECASE)
_DBMS = re.compile(r"Main\s+DBMS\s*:\s*([A-Za-z0-9_.-]+)", re.IGNORECASE)


def _headers(response: dict) -> dict[str, str]:
    return {str(key).lower(): str(value) for key, value in (response.get("headers") or {}).items()}


def _cookie_flags(set_cookie: str) -> tuple[bool, bool, str | None]:
    match = re.search(r"(?:^|[,;\s])ASP\.NET_SessionId=[^;\s,]+(?P<attrs>[^,]*)", set_cookie, re.IGNORECASE)
    if not match:
        return False, False, None
    attrs = match.group("attrs")
    same_site = re.search(r"\bSameSite\s*=\s*([^;\s,]+)", attrs, re.IGNORECASE)
    return True, bool(re.search(r"\bSecure\b", attrs, re.IGNORECASE)), same_site.group(1) if same_site else None


def detect_aspnet_runtime(target_url: str, timeout: int = 12, proxy: str | None = None) -> AspNetRuntimeInfo:
    """Fingerprint legacy ASP.NET and GeneXus from one public GET response."""
    normalized_target = normalize_url(target_url)
    target_parts = urlsplit(normalized_target)
    base_path = target_parts.path or "/"
    if re.search(r"/[^/]+\.[A-Za-z0-9]+$", base_path):
        base_path = base_path.rsplit("/", 1)[0] or "/"
    application_base = urlunsplit((target_parts.scheme, target_parts.netloc, base_path, "", ""))
    client = HttpClient(base_url=application_base, timeout=timeout, proxy=proxy)
    response = client.get("/")
    responses = [response]
    selected_path = "/"
    root_body = str(response.get("body", ""))[:512_000]
    candidate_paths: list[str] = []
    for match in re.finditer(r"(?:href|src)\s*=\s*['\"]([^'\"]+)['\"]", root_body, re.IGNORECASE):
        candidate = match.group(1).strip()
        parsed = urlsplit(candidate)
        if parsed.scheme or parsed.netloc or candidate.startswith(("#", "javascript:", "mailto:")):
            continue
        path = parsed.path or "/"
        if not candidate.startswith("/") and not re.search(r"\.(?:aspx?|html?)$", path, re.IGNORECASE):
            continue
        if path != "/" and path not in candidate_paths:
            candidate_paths.append(path)
        if len(candidate_paths) >= 12:
            break
    for match in re.finditer(
        r"(?:document\.)?location(?:\.href)?\s*=\s*['\"]([^'\"]+)['\"]", root_body, re.IGNORECASE
    ):
        candidate = match.group(1).strip()
        parsed = urlsplit(candidate)
        if parsed.scheme or parsed.netloc or candidate.startswith(("#", "javascript:", "mailto:")):
            continue
        path = parsed.path or "/"
        if path != "/" and path not in candidate_paths:
            candidate_paths.append(path)
        if len(candidate_paths) >= 12:
            break
    # A common portal layout links the generated application below a short
    # sub-path. Keep this bounded and let the link-derived paths win first.
    for path in candidate_paths + ["/portal/"]:
        if any(str(item.get("body", "")).strip() for item in responses if item.get("final_url", "").rstrip("/").endswith(path.rstrip("/"))):
            continue
        candidate_response = client.get(path)
        responses.append(candidate_response)
        candidate_body = str(candidate_response.get("body", ""))
        candidate_headers = _headers(candidate_response)
        if (
            candidate_headers.get("x-aspnet-version")
            or "GeneXus" in candidate_body
            or re.search(r"\b(?:gxgral|gxcfg|gx\.evt)\b", candidate_body, re.IGNORECASE)
        ):
            response = candidate_response
            selected_path = path
            break
    headers = _headers(response)
    body = str(response.get("body", ""))[:512_000]
    asset_bodies: list[str] = []
    final_url = str(response.get("final_url") or target_url)
    for match in re.finditer(r"<script[^>]+src=[\"']([^\"']+)[\"']", body, re.IGNORECASE):
        source = match.group(1).strip()
        if not re.search(r"(?:gxcfg|login)\.js(?:$|\?)", source, re.IGNORECASE):
            continue
        asset = client.get(urljoin(final_url, source))
        if asset.get("status") == 200:
            asset_bodies.append(str(asset.get("body", ""))[:128_000])
        if len(asset_bodies) >= 4:
            break
    fingerprint_body = body + "\n" + "\n".join(asset_bodies)
    asp_version = headers.get("x-aspnet-version") or headers.get("x-aspnetmvc-version")
    server = headers.get("server") or None
    session_cookie, session_secure, session_samesite = _cookie_flags(headers.get("set-cookie", ""))
    powered_by_aspnet = "asp.net" in headers.get("x-powered-by", "").lower()
    detected = bool(asp_version or powered_by_aspnet or session_cookie or (server and "asp.net" in server.lower()))
    sources = []
    source_prefix = selected_path if selected_path.startswith("/") else f"/{selected_path}"
    if asp_version:
        sources.append(f"{source_prefix}:X-AspNet-Version")
    if powered_by_aspnet:
        sources.append(f"{source_prefix}:X-Powered-By")
    if session_cookie:
        sources.append(f"{source_prefix}:Set-Cookie")
    generator_match = _GENERATOR.search(fingerprint_body)
    version_match = _VERSION_META.search(fingerprint_body)
    comment_match = _GENERATOR_COMMENT.search(fingerprint_body)
    raw_generator = generator_match.group(1).strip() if generator_match else None
    # A generic HTML generator is not evidence of GeneXus. In particular,
    # WordPress plugins such as WP Rocket commonly occupy this meta tag.
    generator = raw_generator if raw_generator and "genexus" in raw_generator.lower() else None
    genexus_version = version_match.group(1).strip() if version_match else None
    if comment_match:
        generator = generator or f"GeneXus {comment_match.group(1)}"
        genexus_version = genexus_version or comment_match.group(2)
    genexus_detected = bool(
        (generator and "genexus" in generator.lower())
        or comment_match
        or re.search(r"\b(?:gxgral|gxcfg|gx\.evt)\b", fingerprint_body, re.IGNORECASE)
    )
    dbms_match = _DBMS.search(fingerprint_body)
    dbms = dbms_match.group(1).lower() if dbms_match else None
    gx_sources = []
    if generator or comment_match:
        gx_sources.append(f"{source_prefix}:html")
    if re.search(r"\b(?:gxgral|gxcfg|gx\.evt)\b", fingerprint_body, re.IGNORECASE):
        gx_sources.append(f"{source_prefix}:GeneXus-assets")
    return AspNetRuntimeInfo(
        detected=detected,
        version=asp_version,
        source=",".join(sources) or "not-detected",
        server=server,
        session_cookie=session_cookie,
        session_secure=session_secure,
        session_samesite=session_samesite,
        genexus_detected=genexus_detected,
        genexus_version=genexus_version,
        genexus_generator=generator,
        genexus_dbms=dbms,
        genexus_source=",".join(gx_sources) or "not-detected",
    )


__all__ = ["detect_aspnet_runtime"]
