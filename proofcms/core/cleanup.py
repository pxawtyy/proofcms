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
