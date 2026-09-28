from __future__ import annotations

from ..core.http import probe_target_baseline
from ..core.models import CMSInfo
from .joomla import (
    detect_baforms,
    detect_helix3,
    detect_helixultimate,
    detect_icagenda,
    detect_joomla,
    detect_pagebuilderck,
    detect_rsfiles,
    detect_sppagebuilder,
    joomla_signal_score,
    scan_joomla,
    validate_joomla_manifest,
)
from .joomla import (
    detect_plugins as detect_joomla_plugins,
)
from .wordpress import (
    detect_wordpress,
    detect_wordpress_plugins,
    detect_wordpress_theme,
    parse_wordpress_plugin_version,
    wordpress_signal_score,
)


def detect_cms(target: str, args, baseline: dict | None = None) -> CMSInfo:
    """Unified detector that disambiguates whether a target is Joomla, WordPress, or unknown."""
    if baseline is None:
        baseline = probe_target_baseline(target, timeout=args.timeout, proxy=args.proxy)
    mode = getattr(args, "cms", "auto")
    if mode == "joomla":
        joomla = detect_joomla(target, args, baseline=baseline)
        return CMSInfo("joomla", joomla.detected, joomla.version, joomla.source, joomla.raw)

    if mode == "wordpress":
        wordpress = detect_wordpress(target, args.timeout, proxy=args.proxy, baseline=baseline)
        return wordpress

    wordpress = detect_wordpress(target, args.timeout, proxy=args.proxy, baseline=baseline)
    joomla = detect_joomla(target, args, baseline=baseline)

    if wordpress.detected and not joomla.detected:
        return wordpress
    if joomla.detected and not wordpress.detected:
        return CMSInfo("joomla", True, joomla.version, joomla.source, joomla.raw)
    if wordpress.detected and joomla.detected:
        wp_score = wordpress_signal_score(wordpress)
        j_score = joomla_signal_score(joomla)
        if wp_score >= j_score:
            return wordpress
        return CMSInfo("joomla", True, joomla.version, joomla.source, joomla.raw)

    return CMSInfo("unknown", False, None, "cms:auto", "")


__all__ = [
    "detect_baforms",
    "detect_cms",
    "detect_helix3",
    "detect_helixultimate",
    "detect_icagenda",
    "detect_joomla",
    "detect_joomla_plugins",
    "detect_pagebuilderck",
    "detect_rsfiles",
    "detect_sppagebuilder",
    "detect_wordpress",
    "detect_wordpress_plugins",
    "detect_wordpress_theme",
    "joomla_signal_score",
    "parse_wordpress_plugin_version",
    "scan_joomla",
    "validate_joomla_manifest",
    "wordpress_signal_score",
]
