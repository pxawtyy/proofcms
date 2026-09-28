from __future__ import annotations

import re

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version


def normalize_version_string(version: str | None) -> str | None:
    """Normalize version string by removing prefixes, trailing build letters, etc."""
    if not version:
        return None
    v = str(version).strip()
    # Remove leading 'v' or 'v.'
    v = re.sub(r"^v\.?", "", v, flags=re.IGNORECASE)
    # Remove trailing release suffix like 'v1' (e.g. 1.5.21v1 -> 1.5.21)
    v = re.sub(r"v\d+$", "", v, flags=re.IGNORECASE)
    # Normalize pre-releases to PEP 440 formats (e.g. -rc1 -> rc1, -beta.1 -> b1)
    v = re.sub(r"[-._](rc|preview|pre)[-._]?(\d*)", r"rc\2", v, flags=re.IGNORECASE)
    v = re.sub(r"[-._](beta|b)[-._]?(\d*)", r"b\2", v, flags=re.IGNORECASE)
    v = re.sub(r"[-._](alpha|a)[-._]?(\d*)", r"a\2", v, flags=re.IGNORECASE)
    v = re.sub(r"[-._](dev)[-._]?(\d*)", r"dev\2", v, flags=re.IGNORECASE)
    return v


def parse_version_safe(version: str | None) -> Version | None:
    """Safely parse a version string into a packaging Version object, or None if unparseable."""
    if not version:
        return None
    norm = normalize_version_string(version)
    if not norm:
        return None
    try:
        return Version(norm)
    except InvalidVersion:
        return None


def version_parts(version: str | None) -> list[int] | None:
    """Legacy helper: returns integer parts of version, or None."""
    parsed = parse_version_safe(version)
    if parsed is not None:
        return list(parsed.release)
    return None


def version_in_specifier(version: str | None, specifier_str: str) -> bool | None:
    """Check if version matches a PEP 440 specifier (e.g., '<=1.5.21')."""
    parsed = parse_version_safe(version)
    if parsed is None:
        return None
    try:
        return parsed in SpecifierSet(specifier_str)
    except (InvalidSpecifier, TypeError, ValueError):
        return None


def version_lte(left: str | None, right: str | None) -> bool:
    v_left = parse_version_safe(left)
    v_right = parse_version_safe(right)
    if v_left is None or v_right is None:
        return False
    return v_left <= v_right


def version_lt(left: str | None, right: str | None) -> bool:
    v_left = parse_version_safe(left)
    v_right = parse_version_safe(right)
    if v_left is None or v_right is None:
        return False
    return v_left < v_right


def version_gte(left: str | None, right: str | None) -> bool:
    v_left = parse_version_safe(left)
    v_right = parse_version_safe(right)
    if v_left is None or v_right is None:
        return False
    return v_left >= v_right


def version_gt(left: str | None, right: str | None) -> bool:
    v_left = parse_version_safe(left)
    v_right = parse_version_safe(right)
    if v_left is None or v_right is None:
        return False
    return v_left > v_right
