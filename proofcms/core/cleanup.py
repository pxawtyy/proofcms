"""Lab-cleanup hook convention for aggressive probes that create artifacts.

In-probe cleanup already removes what it can, but interrupted runs,
undeletable dotfiles, and hash directories leave leftovers that reports
could only describe as "delete manually". A module opts in by exposing::

    def cleanup(
        target_url: str,
        *,
        timeout: int = 12,
        proxy: str | None = None,
        aggressive_args: dict | None = None,
        aggressive_command: str | None = None,
    ) -> dict[str, Any]: ...

The hook re-derives artifact locations from ``aggressive_args`` (exact names
saved from the probe report) or sweeps the module's known path patterns for
``proofcms-*`` leftovers. It returns ``cleanup_result(...)``: ``removed``
paths the hook deleted over HTTP, ``remaining`` paths still present, and
``manual`` shell commands for what HTTP cannot delete. ``ok`` is True only
when nothing remains and nothing needs manual work.
"""

from __future__ import annotations

from typing import Any


def cleanup_result(
    *,
    removed: list[str] | None = None,
    remaining: list[str] | None = None,
    manual: list[str] | None = None,
    detail: str = "",
) -> dict[str, Any]:
    """Build the standard lab-cleanup result mapping."""
    removed = list(removed or [])
    remaining = list(remaining or [])
    manual = list(manual or [])
    return {
        "removed": removed,
        "remaining": remaining,
        "manual": manual,
        "ok": not remaining and not manual,
        "detail": detail
        or (
            "Cleanup complete; no artifacts remain."
            if not remaining and not manual
            else f"Removed {len(removed)} artifact(s); {len(remaining)} remaining, {len(manual)} manual step(s)."
        ),
    }


def cleanup_http_artifact(
    target_url: str,
    *,
    timeout: int = 12,
    proxy: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    aggressive_command: str | None = None,
    label: str = "uploaded file",
) -> dict[str, Any]:
    """Verify an uploaded artifact over HTTP and report what cannot be deleted.

    Most CMS upload directories are served statically, so the probe cannot
    unlink the file through the application. The hook still checks whether the
    artifact is present, which lets ``--lab-cleanup`` distinguish an already
    clean lab from a leftover file that needs a manual shell command.
    """
    from .args import aggressive_value
    from .http import HttpClient, is_transport_error, normalize_url

    raw = (
        aggressive_value(aggressive_args, aggressive_command, "file")
        or aggressive_value(aggressive_args, aggressive_command, "path")
        or aggressive_value(aggressive_args, aggressive_command, "url")
    )
    if not raw:
        return cleanup_result(
            manual=[
                "re-run with --aggressive-arg file=<uploaded_filename or proof URL> from the probe evidence"
            ],
            detail="Missing file/path argument; nothing was attempted.",
        )

    base = normalize_url(target_url)
    urls: list[str] = []
    for item in str(raw).split(","):
        value = item.strip()
        if not value:
            continue
        if value.startswith(("http://", "https://")):
            urls.append(value)
        else:
            urls.append(f"{base}/{value.lstrip('/')}")

    removed: list[str] = []
    remaining: list[str] = []
    manual: list[str] = []
    client = HttpClient(timeout=timeout, proxy=proxy)
    for url in urls:
        response = client.get(url, timeout=timeout)
        if not is_transport_error(response) and response.get("status") == 200:
            remaining.append(url)
            manual.append(f"delete the {label}: {url}")
        else:
            removed.append(url)
    return cleanup_result(removed=removed, remaining=remaining, manual=manual)
