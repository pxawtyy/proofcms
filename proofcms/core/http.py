from __future__ import annotations

import hashlib
import http.cookiejar
import random
import secrets
import ssl
import string
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, cast

DEFAULT_USER_AGENT = "ProofCMS/2.1 authorized-audit"


def normalize_url(url: str, timeout: int = 0, proxy: str | None = None) -> str:
    """Normalize URL by adding scheme if missing and trimming trailing slash."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    normalized = url.rstrip("/")

    # If timeout > 0, probe if https works or fallback to http
    if timeout > 0 and url.startswith("https://"):
        try:
            req = urllib.request.Request(
                normalized,
                headers={"User-Agent": DEFAULT_USER_AGENT},
            )
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            handlers: list[urllib.request.BaseHandler] = [urllib.request.HTTPSHandler(context=ctx)]
            if proxy:
                handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
            opener = urllib.request.build_opener(*handlers)
            with opener.open(req, timeout=timeout):
                return normalized
        except urllib.error.HTTPError:
            # Server responded with an HTTP status code (e.g. 401, 403, 404, 500) over HTTPS.
            # HTTPS connection works; do not fall back to plain HTTP.
            return normalized
        except (urllib.error.URLError, ssl.SSLError, OSError, TimeoutError, ConnectionError):
            return "http://" + normalized.split("://", 1)[1]
        except Exception:  # noqa: BLE001
            return "http://" + normalized.split("://", 1)[1]

    return normalized


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
    headers: dict[str, Any] | None = None,
    raw_bytes: bytes = b"",
) -> dict[str, Any]:
    headers_dict: dict[str, Any] = headers or {}
    content_type = headers_dict.get("Content-Type", "")
    body_hash = hashlib.sha256(raw_bytes if raw_bytes else body.encode("utf-8", errors="replace")).hexdigest()
    return {
        "status": status,
        "body": body,
        "url": final_url,
        "requested_url": requested_url,
        "final_url": final_url,
        "redirected": (requested_url.rstrip("/") != final_url.rstrip("/")),
        "headers": headers_dict,
        "content_type": content_type,
        "body_hash": body_hash,
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
    ):
        self.base_url = normalize_url(base_url) if base_url else None
        self.timeout = timeout
        self.proxy = proxy
        self.user_agent = user_agent
        self.jar = http.cookiejar.CookieJar()
        self._rebuild_opener()

    def _rebuild_opener(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers: list[urllib.request.BaseHandler] = [
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(self.jar),
        ]
        if self.proxy:
            handlers.append(urllib.request.ProxyHandler({"http": self.proxy, "https": self.proxy}))
        self.opener = urllib.request.build_opener(*handlers)

    def _resolve_url(self, url: str) -> str:
        if self.base_url and not url.startswith(("http://", "https://")):
            path = url if url.startswith("/") else f"/{url}"
            return f"{self.base_url}{path}"
        return url

    def request(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, Any] | None = None,
        data: bytes | str | None = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        full_url = self._resolve_url(url)
        req_headers: dict[str, Any] = {"User-Agent": self.user_agent}
        if headers:
            req_headers.update(headers)

        payload_bytes: bytes | None = None
        if data is not None:
            payload_bytes = data if isinstance(data, bytes) else data.encode("utf-8")

        req = urllib.request.Request(full_url, method=method, headers=req_headers, data=payload_bytes)
        effective_timeout = timeout if timeout is not None else self.timeout

        try:
            with self.opener.open(req, timeout=effective_timeout) as response:
                body_bytes = response.read(512 * 1024)
                body = body_bytes.decode("utf-8", errors="replace")
                final_url: str = response.url or full_url
                resp_headers = dict(response.headers)
                return _build_response_dict(response.status, body, full_url, final_url, resp_headers, body_bytes)
        except urllib.error.HTTPError as exc:
            body_bytes = exc.read(512 * 1024) if hasattr(exc, "read") else b""
            body = body_bytes.decode("utf-8", errors="replace")
            final_url = exc.url if exc.url else full_url
            resp_headers = dict(exc.headers) if hasattr(exc, "headers") and exc.headers else {}
            return _build_response_dict(exc.code, body, full_url, final_url, resp_headers, body_bytes)
        except Exception as exc:  # noqa: BLE001
            return _build_response_dict(0, str(exc), full_url, full_url, {})

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
    client = HttpClient(timeout=timeout, proxy=proxy)
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
    resp = fetch_url(canary_url, timeout=timeout, proxy=proxy)
    target_root = target.rstrip("/")
    final = resp.get("final_url", "").rstrip("/")
    redirected_to_root = final in (target_root, f"{target_root}/index.php")
    return {
        "status": resp.get("status", 0),
        "blanket_403": resp.get("status") == 403,
        "redirected_to_root": redirected_to_root,
        "body_hash": resp.get("body_hash", ""),
        "body_len": len(resp.get("body", "")),
        "target_root": target_root,
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
            attempts += 1
            resp = fetch_fn(path)
            if resp and resp.get("status") == 200:
                return resp, path, attempts
        time.sleep(current_delay)
        current_delay = min(current_delay * backoff, max_delay)

    return None, None, attempts
