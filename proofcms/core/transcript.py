"""Proof transcripts: automatic request/response capture for VULNERABLE findings.

Evidence dicts were hand-assembled per module with varying shapes, so
reports were not comparable and the exact request sequence was lost once
the gitignored text report expired. Two pieces fix that:

* ``HttpClient`` records a lightweight entry per exchange (method, URLs,
  status, body hash/length — never bodies, so secrets stay out).
* the stateless ``request()`` helper keeps a thread-local ring of the same
  shape for modules that do not hold a session.

Modules attach the transcript in one line when building a VULNERABLE (or
VULNERABLE_UPLOAD_ONLY) finding via ``attach_transcript`` or the
``transcript=`` parameter of ``differential.evidence_from``. Entries flow
through the standard ``evidence`` dict into JSON and text reports, where
the existing redaction already scrubs embedded credentials.
"""

from __future__ import annotations

import hashlib
import threading
import urllib.parse
from typing import Any

MAX_ENTRIES = 50

STATELESS_KEY = "transcript"
_thread_state = threading.local()


def _scrub_url(url: str) -> str:
    try:
        parts = urllib.parse.urlsplit(url or "")
    except ValueError:
        return url
    if parts.username is None and "@" not in (parts.netloc or ""):
        return url
    host = parts.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host + (f":{parts.port}" if parts.port else "")
    return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def make_entry(
    method: str,
    requested_url: str,
    response: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build one transcript entry from a request and its response dict."""
    response = response or {}
    body = response.get("body", "")
    entry: dict[str, Any] = {
        "method": (method or "GET").upper(),
        "url": _scrub_url(str(requested_url)),
        "status": response.get("status", 0),
        "body_len": len(body) if isinstance(body, str) else 0,
    }
    final_url = response.get("final_url")
    if final_url and str(final_url) != str(requested_url):
        entry["final_url"] = _scrub_url(str(final_url))
    raw = body if isinstance(body, str) else ""
    entry["body_hash"] = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]
    error = response.get("error")
    if error:
        entry["error"] = str(error.get("type") if isinstance(error, dict) else error)
    return entry


def _ring() -> list[dict[str, Any]]:
    entries = getattr(_thread_state, STATELESS_KEY, None)
    if entries is None:
        entries = []
        setattr(_thread_state, STATELESS_KEY, entries)
    return entries


def record_stateless(method: str, requested_url: str, response: dict[str, Any] | None) -> None:
    """Append one entry to the thread-local stateless ring (bounded)."""
    entries = _ring()
    entries.append(make_entry(method, requested_url, response))
    del entries[: max(0, len(entries) - MAX_ENTRIES)]


def take_transcript() -> list[dict[str, Any]]:
    """Return and clear the thread-local stateless transcript."""
    entries = _ring()
    snapshot = list(entries)
    del entries[:]
    return snapshot


def take_client_transcript(client: Any, limit: int = 12) -> list[dict[str, Any]]:
    """Return the tail of a session client's transcript without clearing it."""
    entries = list(getattr(client, "transcript", None) or [])
    return entries[-limit:] if limit and len(entries) > limit else entries


def attach_transcript(
    evidence: dict[str, Any] | None,
    entries: list[dict[str, Any]] | Any,
    limit: int = 12,
) -> dict[str, Any]:
    """Attach request/response entries under the ``transcript`` key.

    ``entries`` is either a transcript list or an ``HttpClient`` (whose tail
    is taken). Returns the evidence dict for inline use.
    """
    evidence = dict(evidence or {})
    if not isinstance(entries, list):
        entries = take_client_transcript(entries, limit=limit)
    elif limit and len(entries) > limit:
        entries = entries[-limit:]
    evidence[STATELESS_KEY] = entries
    return evidence
