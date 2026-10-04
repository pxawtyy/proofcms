from __future__ import annotations

import hashlib
import http.cookiejar
import random
import re
import secrets
import ssl
import string
import threading
import urllib.error
import urllib.parse
import urllib.request
import zlib
from typing import Any, cast

DEFAULT_USER_AGENT = "ProofCMS/2.1 authorized-audit"
DEFAULT_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
DEFAULT_ACCEPT_LANGUAGE = "en-US,en;q=0.9,pt-BR;q=0.8"
MAX_RESPONSE_BYTES = 512 * 1024
_TLS_VERIFY = True
_thread_clients = threading.local()


def configure_tls(verify: bool = True) -> None:
    """Set the process-wide TLS policy used by newly created clients."""
    global _TLS_VERIFY
    _TLS_VERIFY = verify
    _thread_clients.clients = {}


def reset_transport_state() -> None:
    """Drop thread-local clients so cookies never cross target boundaries."""
    _thread_clients.clients = {}


def detect_edge_interstitial(body: str, final_url: str = "") -> str | None:
    """Identify known bot/WAF challenge pages that commonly return HTTP 200."""
    haystack = f"{final_url}\n{body[:128 * 1024]}".lower()
    markers = {
        "radware-bot-manager": (
            "validate.perfdrive.com",
            "radware captcha page",
            "shieldsquare",
            "__uzma",
            "__uzmb",
        ),
    }
    for provider, provider_markers in markers.items():
        if any(marker in haystack for marker in provider_markers):
            return provider
    return None


def _normalize_dynamic_html(body: str) -> str:
    """Remove common per-request values before comparing fake-200 pages."""
    normalized = re.sub(r"\b[a-f0-9]{32}\b", "<joomla-token>", body, flags=re.IGNORECASE)
    normalized = re.sub(
        r"([?&](?:token|nonce|sid|session(?:id)?)=)[^&\"'<>\s]+",
        r"\1<dynamic>",
        normalized,
        flags=re.IGNORECASE,
    )
    return re.sub(r"\s+", " ", normalized).strip()


def _html_title(body: str) -> str:
    match = re.search(r"<title\b[^>]*>(.*?)</title>", body, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip().lower()


def _decode_body(body_bytes: bytes, headers: Any) -> tuple[bytes, str, bool]:
    """Decode bounded content encoding and character encoding metadata."""
    encoding = str(headers.get("Content-Encoding", "")).lower()
    decoded_bytes = body_bytes
    encoding_truncated = False
    if encoding in {"gzip", "deflate"}:
        try:
            window = 16 + zlib.MAX_WBITS if encoding == "gzip" else zlib.MAX_WBITS
            decompressor = zlib.decompressobj(window)
            decoded_bytes = decompressor.decompress(body_bytes, MAX_RESPONSE_BYTES + 1)
            encoding_truncated = len(decoded_bytes) > MAX_RESPONSE_BYTES or bool(decompressor.unconsumed_tail)
            decoded_bytes = decoded_bytes[:MAX_RESPONSE_BYTES]
        except zlib.error:
            decoded_bytes = body_bytes
    charset = headers.get_content_charset() if hasattr(headers, "get_content_charset") else None
    try:
        body = decoded_bytes.decode(charset or "utf-8", errors="replace")
    except LookupError:
        body = decoded_bytes.decode("utf-8", errors="replace")
    return decoded_bytes, body, encoding_truncated


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def normalize_url(url: str, timeout: int = 0, proxy: str | None = None) -> str:
    """Validate and normalize an HTTP(S) target without performing network I/O."""
    del timeout, proxy  # retained for API compatibility
    value = url.strip()
    if not value:
        raise ValueError("target URL is empty")
    if "://" not in value:
        value = "https://" + value
    parsed = urllib.parse.urlsplit(value)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError(f"unsupported URL scheme: {parsed.scheme or '(missing)'}")
    if not parsed.hostname:
        raise ValueError("target URL must include a hostname")
    if parsed.query or parsed.fragment:
        raise ValueError("target URL must not include a query string or fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid target port: {exc}") from exc
    host = parsed.hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    userinfo = ""
    if parsed.username is not None:
        userinfo = urllib.parse.quote(parsed.username, safe="")
        if parsed.password is not None:
            userinfo += ":" + urllib.parse.quote(parsed.password, safe="")
        userinfo += "@"
    netloc = f"{userinfo}{host}{f':{port}' if port is not None else ''}"
    path = re.sub(r"/{2,}", "/", parsed.path or "").rstrip("/")
    return urllib.parse.urlunsplit((scheme, netloc, path, "", ""))


def build_multipart(fields: dict, files: dict) -> tuple[str, bytes]:
    """
    Constructs a multipart/form-data payload with boundary.
    fields: dict of {name: value}
    files: dict of {field_name: (filename, data, content_type)}
    Returns: (content_type_header_val, body_bytes)
    """
    boundary = "".join(random.choices(string.ascii_letters + string.digits, k=32))
    body = b""
    for name, value in fields.items():
        body += f"--{boundary}\r\n".encode("latin-1")
        body += f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("latin-1")
        body += str(value).encode("utf-8") + b"\r\n"
    for field_name, (filename, data, content_type) in files.items():
        body += f"--{boundary}\r\n".encode("latin-1")
        body += (
            f'Content-Disposition: form-data; name="{field_name}"; '
            f'filename="{filename}"\r\n'
        ).encode("latin-1")
        body += f"Content-Type: {content_type}\r\n\r\n".encode("latin-1")
        body += data if isinstance(data, bytes) else data.encode("utf-8")
        body += b"\r\n"
    body += f"--{boundary}--\r\n".encode("latin-1")
    return f"multipart/form-data; boundary={boundary}", body


def form_encode(fields: dict) -> bytes:
    """Encode form fields into URL-encoded bytes."""
    return urllib.parse.urlencode(fields).encode("utf-8")


def _build_response_dict(
    status: int,
    body: str,
    requested_url: str,
    final_url: str,
    headers: Any = None,
    raw_bytes: bytes = b"",
    *,
    error: dict[str, str] | None = None,
    truncated: bool = False,
) -> dict[str, Any]:
    headers_dict: dict[str, Any] = dict(headers) if headers else {}
    header_items = list(headers.items()) if hasattr(headers, "items") else list(headers_dict.items())
    headers_multi: dict[str, list[str]] = {}
    for key, value in header_items:
        headers_multi.setdefault(str(key).lower(), []).append(str(value))
    content_type = next(
        (str(value) for key, value in headers_dict.items() if key.lower() == "content-type"),
        "",
    )
    body_hash = hashlib.sha256(raw_bytes if raw_bytes else body.encode("utf-8", errors="replace")).hexdigest()
    normalized_body = _normalize_dynamic_html(body)
    return {
        "status": status,
        "body": body,
        "url": final_url,
        "requested_url": requested_url,
        "final_url": final_url,
        "redirected": (requested_url.rstrip("/") != final_url.rstrip("/")),
        "headers": headers_dict,
        "headers_multi": headers_multi,
        "content_type": content_type,
        "body_hash": body_hash,
        "normalized_body_hash": hashlib.sha256(normalized_body.encode("utf-8")).hexdigest(),
        "body_len": len(body),
        "title": _html_title(body),
        "edge_interstitial": detect_edge_interstitial(body, final_url),
        "error": error,
        "truncated": truncated,
        "captured_bytes": len(raw_bytes),
    }


class HttpClient:
    """
    Unified HTTP client supporting cookie persistence, proxy routing,
    SSL bypass for lab environments, and custom headers.
    """

    def __init__(
        self,
        base_url: str | None = None,
        timeout: int = 12,
        proxy: str | None = None,
        user_agent: str = DEFAULT_USER_AGENT,
        verify_tls: bool | None = None,
    ):
        self.base_url = normalize_url(base_url) if base_url else None
        self.timeout = timeout
        self.proxy = proxy
        self.user_agent = user_agent
        self.verify_tls = _TLS_VERIFY if verify_tls is None else verify_tls
        self.jar = http.cookiejar.CookieJar()
        self._rebuild_opener()

    def _rebuild_opener(self):
        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        handlers: list[urllib.request.BaseHandler] = [
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(self.jar),
        ]
        if self.proxy:
            handlers.append(urllib.request.ProxyHandler({"http": self.proxy, "https": self.proxy}))
        self.opener = urllib.request.build_opener(*handlers)
        self.no_redirect_opener = urllib.request.build_opener(_NoRedirectHandler(), *handlers)

    def _resolve_url(self, url: str) -> str:
        if self.base_url and not url.startswith(("http://", "https://")):
            base = self.base_url.rstrip("/") + "/"
            return urllib.parse.urljoin(base, url.lstrip("/"))
        return url

    def request(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, Any] | None = None,
        data: bytes | str | None = None,
        timeout: int | None = None,
        follow_redirects: bool = True,
    ) -> dict[str, Any]:
        full_url = self._resolve_url(url)
        req_headers: dict[str, Any] = {
            "User-Agent": self.user_agent,
            "Accept": DEFAULT_ACCEPT,
            "Accept-Language": DEFAULT_ACCEPT_LANGUAGE,
        }
        if headers:
            req_headers.update(headers)

        payload_bytes: bytes | None = None
        if data is not None:
            payload_bytes = data if isinstance(data, bytes) else data.encode("utf-8")

        effective_timeout = timeout if timeout is not None else self.timeout

        try:
            req = urllib.request.Request(full_url, method=method, headers=req_headers, data=payload_bytes)
            opener = self.opener if follow_redirects else self.no_redirect_opener
            with opener.open(req, timeout=effective_timeout) as response:
                body_bytes = response.read(MAX_RESPONSE_BYTES + 1)
                truncated = len(body_bytes) > MAX_RESPONSE_BYTES
                body_bytes = body_bytes[:MAX_RESPONSE_BYTES]
                body_bytes, body, encoding_truncated = _decode_body(body_bytes, response.headers)
                truncated = truncated or encoding_truncated
                final_url: str = response.url or full_url
                return _build_response_dict(
                    response.status, body, full_url, final_url, response.headers, body_bytes, truncated=truncated
                )
        except urllib.error.HTTPError as exc:
            body_bytes = exc.read(MAX_RESPONSE_BYTES + 1) if hasattr(exc, "read") else b""
            truncated = len(body_bytes) > MAX_RESPONSE_BYTES
            body_bytes = body_bytes[:MAX_RESPONSE_BYTES]
            body_bytes, body, encoding_truncated = _decode_body(body_bytes, exc.headers or {})
            truncated = truncated or encoding_truncated
            final_url = exc.url if exc.url else full_url
            return _build_response_dict(
                exc.code, body, full_url, final_url, exc.headers or {}, body_bytes, truncated=truncated
            )
        except Exception as exc:  # noqa: BLE001
            return _build_response_dict(
                0,
                "",
                full_url,
                full_url,
                {},
                error={"type": type(exc).__name__, "message": str(exc)},
            )

    def get(self, url: str, headers: dict[str, Any] | None = None, timeout: int | None = None) -> dict[str, Any]:
        return self.request(url, method="GET", headers=headers, timeout=timeout)

    def post(
        self,
        url: str,
        data: bytes | str | dict[str, Any] | None = None,
        fields: dict[str, Any] | None = None,
        files: dict[str, Any] | None = None,
        headers: dict[str, Any] | None = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        if files:
            return self.post_multipart(url, fields=fields or {}, files=files, headers=headers, timeout=timeout)
        post_headers: dict[str, Any] = dict(headers or {})
        post_data: bytes | str | None
        if fields:
            post_data = form_encode(fields)
            post_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif isinstance(data, dict):
            post_data = form_encode(data)
            post_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        else:
            post_data = data
        return self.request(url, method="POST", headers=post_headers, data=post_data, timeout=timeout)

    def post_multipart(
        self,
        url: str,
        fields: dict[str, Any],
        files: dict[str, Any],
        headers: dict[str, Any] | None = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        content_type, body = build_multipart(fields, files)
        post_headers: dict[str, Any] = dict(headers or {})
        post_headers["Content-Type"] = content_type
        return self.request(url, method="POST", headers=post_headers, data=body, timeout=timeout)


# Backwards-compatible alias for session-style HTTP client
HttpSession = HttpClient


def request(
    url: str,
    method: str = "GET",
    headers: dict[str, Any] | None = None,
    data: bytes | str | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> dict[str, Any]:
    """Convenience function for stateless HTTP requests matching legacy modules."""
    key = (timeout, proxy, _TLS_VERIFY)
    clients = getattr(_thread_clients, "clients", None)
    if clients is None:
        clients = {}
        _thread_clients.clients = clients
    client = clients.get(key)
    if client is None:
        client = HttpClient(timeout=timeout, proxy=proxy)
        clients[key] = client
    return client.request(url, method=method, headers=headers, data=data, timeout=timeout)


def fetch_url(url: str, timeout: int = 12, proxy: str | None = None, session: Any = None) -> dict[str, Any]:
    """Convenience function for fetching a URL through the shared client."""
    if session is not None and hasattr(session, "get"):
        return cast(dict[str, Any], session.get(url, timeout=timeout))
    return request(url, method="GET", timeout=timeout, proxy=proxy)


def probe_target_baseline(target: str, timeout: int = 8, proxy: str | None = None) -> dict[str, Any]:
    """Probes target baseline behavior using a random nonce canary path."""
    nonce = secrets.token_hex(6)
    canary_path = f"/_jvh_probe_{nonce}/"
    canary_url = f"{target.rstrip('/')}{canary_path}"
    root_response = fetch_url(f"{target.rstrip('/')}/", timeout=timeout, proxy=proxy)
    resp = fetch_url(canary_url, timeout=timeout, proxy=proxy)
    target_root = target.rstrip("/")
    final = resp.get("final_url", "").rstrip("/")
    redirected_to_root = final in (target_root, f"{target_root}/index.php")
    return {
        "status": resp.get("status", 0),
        "blanket_403": resp.get("status") == 403,
        "redirected_to_root": redirected_to_root,
        "body_hash": resp.get("body_hash", ""),
        "normalized_body_hash": resp.get("normalized_body_hash", ""),
        "body_len": resp.get("body_len", len(resp.get("body", ""))),
        "title": resp.get("title", ""),
        "target_root": target_root,
        "edge_interstitial": root_response.get("edge_interstitial"),
        "error": resp.get("error") or root_response.get("error"),
    }


def is_baseline_match(response: dict, baseline: dict | None, allow_403: bool = False) -> bool:
    """Determines whether a response matches the target's baseline non-existent path behavior."""
    if not baseline:
        return False
    if response.get("status", 0) <= 0:
        return False
    resp_hash = response.get("body_hash")
    base_hash = baseline.get("body_hash")
    if resp_hash and base_hash and resp_hash == base_hash:
        return True
    normalized_hash = response.get("normalized_body_hash")
    baseline_normalized_hash = baseline.get("normalized_body_hash")
    if normalized_hash and baseline_normalized_hash and normalized_hash == baseline_normalized_hash:
        return True
    # Similar title/length is useful diagnostic context, but is not sufficient
    # to reject a route when the normalized content hashes differ.
    if response.get("redirected") and baseline.get("target_root"):
        final_url = response.get("final_url", "").rstrip("/")
        root_url = baseline.get("target_root", "").rstrip("/")
        if final_url in (root_url, f"{root_url}/index.php"):
            return True
    return bool(response.get("status") == 403 and baseline.get("blanket_403") and not allow_403)


def poll_paths(
    fetch_fn: Any,
    paths: list[str],
    deadline: float = 3.5,
    initial_delay: float = 0.1,
    backoff: float = 1.4,
    max_delay: float = 0.8,
    accept_fn: Any = None,
) -> tuple[dict | None, str | None, int]:
    """
    Polls candidate paths with deadline and backoff to avoid false negatives
    on slow disks, network file systems, or Docker volume sync delays.

    Returns: (successful_response, successful_path, total_attempts)
    """
    import time
    start_time = time.monotonic()
    current_delay = initial_delay
    attempts = 0

    while time.monotonic() - start_time < deadline:
        for path in paths:
            if time.monotonic() - start_time >= deadline:
                return None, None, attempts
            attempts += 1
            resp = fetch_fn(path)
            if resp and resp.get("status") == 200 and (accept_fn is None or accept_fn(resp)):
                return resp, path, attempts
        remaining = deadline - (time.monotonic() - start_time)
        if remaining <= 0:
            break
        time.sleep(min(current_delay, remaining))
        current_delay = min(current_delay * backoff, max_delay)

    return None, None, attempts
