"""Standard ``--aggressive-arg KEY=VALUE`` handling.

``--aggressive-command`` grew a dialect per module (``user:pass``,
bare URLs, ``user|canary|group`` pipes, ``helix3-import:...``). New code
takes named arguments instead: repeatable ``--aggressive-arg KEY=VALUE``
flags parsed once in the CLI and handed to every ``check()`` as the
``aggressive_args`` mapping. Legacy ``aggressive_command`` strings keep
working; migrated modules read the mapping first and fall back to the
old format.
"""

from __future__ import annotations

from typing import Any


def parse_aggressive_args(items: list[str] | None) -> dict[str, str]:
    """Parse ``['KEY=VALUE', ...]`` into a mapping.

    Whitespace around keys and values is stripped. A missing ``=`` or an
    empty key raises ``ValueError`` so typos fail loudly in the CLI instead
    of silently disabling a probe. Duplicate keys also raise: the last
    occurrence winning would hide mistakes.
    """
    parsed: dict[str, str] = {}
    for item in items or []:
        key, separator, value = item.partition("=")
        key = key.strip()
        if not separator or not key:
            raise ValueError(f"invalid --aggressive-arg {item!r}: expected KEY=VALUE")
        if key in parsed:
            raise ValueError(f"duplicate --aggressive-arg key {key!r}")
        parsed[key] = value.strip()
    return parsed


def aggressive_value(
    aggressive_args: dict[str, Any] | None,
    aggressive_command: str | None,
    key: str,
    default: str | None = None,
) -> str | None:
    """Return the named argument, falling back to the legacy command string.

    The legacy string is returned whole (for URL-style commands) or ``None``
    when absent; per-format pipe parsing stays in the migrated module next
    to its documented keys.
    """
    if aggressive_args and key in aggressive_args:
        value = aggressive_args[key]
        return str(value) if value is not None else default
    if key == "command":
        return aggressive_command
    return default
