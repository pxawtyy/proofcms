from __future__ import annotations

import re

from ..core.http import HttpClient
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
    response = HttpClient(base_url=target_url, timeout=timeout, proxy=proxy).get("/")
    headers = _headers(response)
    body = str(response.get("body", ""))[:512_000]
    asp_version = headers.get("x-aspnet-version") or headers.get("x-aspnetmvc-version")
    server = headers.get("server") or None
    session_cookie, session_secure, session_samesite = _cookie_flags(headers.get("set-cookie", ""))
    powered_by_aspnet = "asp.net" in headers.get("x-powered-by", "").lower()
    detected = bool(asp_version or powered_by_aspnet or session_cookie or "asp.net" in server.lower() if server else False)
    sources = []
    if asp_version:
        sources.append("/:X-AspNet-Version")
    if powered_by_aspnet:
        sources.append("/:X-Powered-By")
    if session_cookie:
        sources.append("/:Set-Cookie")
    generator_match = _GENERATOR.search(body)
    version_match = _VERSION_META.search(body)
    comment_match = _GENERATOR_COMMENT.search(body)
    generator = generator_match.group(1).strip() if generator_match else None
    genexus_version = version_match.group(1).strip() if version_match else None
    if comment_match:
        generator = generator or f"GeneXus {comment_match.group(1)}"
        genexus_version = genexus_version or comment_match.group(2)
    genexus_detected = bool(
        (generator and "genexus" in generator.lower())
        or comment_match
        or re.search(r"\b(?:gxgral|gxcfg|gx\.evt)\b", body, re.IGNORECASE)
    )
    dbms_match = _DBMS.search(body)
    dbms = dbms_match.group(1).lower() if dbms_match else None
    gx_sources = []
    if generator_match or comment_match:
        gx_sources.append("/:html")
    if re.search(r"\b(?:gxgral|gxcfg|gx\.evt)\b", body, re.IGNORECASE):
        gx_sources.append("/:GeneXus-assets")
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
