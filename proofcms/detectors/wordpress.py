from __future__ import annotations

import re

from ..core.http import fetch_url, is_baseline_match
from ..core.models import CMSInfo

KNOWN_PLUGIN_MARKERS = {
    "contact-form-7": r"Contact\s+Form\s+7",
    "drag-and-drop-multiple-file-upload-contact-form-7": r"Drag\s+and\s+Drop\s+Multiple\s+File\s+Upload",
    "essential-addons-for-elementor-lite": r"Essential\s+Addons\s+for\s+Elementor",
    "litespeed-cache": r"LiteSpeed\s+Cache",
    "really-simple-ssl": r"Really\s+Simple\s+(?:SSL|Security)",
    "ultimate-member": r"Ultimate\s+Member",
    "woocommerce-payments": r"Woo(?:Commerce\s+)?Payments|WooPayments",
    "revslider": r"Slider\s+Revolution|Revolution\s+Slider|revslider",
    "wp-file-manager": r"(?:WP\s+)?File\s+Manager",
    "keydatas": r"keydatas|简数",
}


def _fetch(url: str, timeout: int, proxy: str | None = None) -> dict:
    return fetch_url(url, timeout=timeout, proxy=proxy)


def detect_wordpress(
    target: str,
    timeout: int,
    proxy: str | None = None,
    baseline: dict | None = None,
) -> CMSInfo:
    """Detects whether target is running WordPress and attempts to determine core version."""
    paths = [
        "/",
        "/wp-json/",
        "/readme.html",
        "/wp-login.php",
        "/wp-admin/",
        "/wp-admin/install.php",
    ]
    version_patterns = [
        r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([^"\']+)',
        r"\bwp-emoji-release(?:\.min)?\.js\?ver=([0-9]+(?:\.[0-9]+){1,3})",
        r"\bwp-admin/(?:load-(?:styles|scripts)\.php|js/[^?\"']+)[^\"']*?(?:\?|&(?:amp;)?)ver=([0-9]+(?:\.[0-9]+){1,3})",
        r"<br\s*/?>\s*Version\s+([0-9]+(?:\.[0-9]+){1,3})",
    ]
    for path in paths:
        response = _fetch(f"{target.rstrip('/')}{path}", timeout=timeout, proxy=proxy)
        if is_baseline_match(response, baseline):
            continue
        status = response.get("status", 0)
        body = response.get("body", "")
        lowered = body.lower()
        source = f"wordpress:{path}"

        version = None
        for pattern in version_patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                version = match.group(1).strip()
                break

        if version:
            return CMSInfo("wordpress", True, version, source, body[:2000])

        if path == "/wp-json/" and status == 200 and re.search(r'"namespaces"\s*:|wp/v2|wp-site-health', body, re.IGNORECASE):
            return CMSInfo("wordpress", True, None, source, body[:2000])

        if path == "/wp-login.php" and status in (200, 302) and re.search(r"wp-login|wordpress|loginform", body, re.IGNORECASE):
            return CMSInfo("wordpress", True, None, source, body[:2000])

        if path == "/wp-admin/" and status in (200, 302) and re.search(r"wp-admin|wordpress|wp-login", body, re.IGNORECASE):
            return CMSInfo("wordpress", True, None, source, body[:2000])

        if path == "/" and (
            "wp-content/" in lowered
            or "wp-includes/" in lowered
            or re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress', body, re.IGNORECASE)
        ):
            return CMSInfo("wordpress", True, None, source, body[:2000])

    return CMSInfo("wordpress", False, None, "wordpress:fallback", "")


def wordpress_signal_score(info: CMSInfo) -> int:
    if not info.detected:
        return 0
    score = 1
    if info.version:
        score += 3
    if info.source in {"wordpress:/", "wordpress:/wp-json/", "wordpress:/readme.html"}:
        score += 3
    if info.source in {"wordpress:/wp-login.php", "wordpress:/wp-admin/"}:
        score += 2
    if re.search(r"wp-content|wp-includes|wp-json|wp-login|wp-admin|wordpress", info.raw or "", re.IGNORECASE):
        score += 2
    return score


def parse_wordpress_plugin_version(body: str) -> str | None:
    patterns = [
        r"^\s*Stable\s+tag:\s*([^\r\n<]+)",
        r"^\s*Version:\s*([^\r\n<]+)",
        r'"version"\s*:\s*"([^"]+)"',
        r"Plugin\s+URI:.*?\b([0-9]+(?:\.[0-9]+){1,3})\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, body, re.IGNORECASE | re.MULTILINE | re.DOTALL)
        if match:
            value = match.group(1).strip()
            if value and value.lower() not in {"trunk", "latest"}:
                return value
    return None


def detect_wordpress_theme(
    target: str,
    html: str,
    timeout: int,
    proxy: str | None = None,
    baseline: dict | None = None,
) -> dict:
    theme_match = re.search(r"/wp-content/themes/([A-Za-z0-9_-]+)/", html, re.IGNORECASE)
    if not theme_match:
        return {"found": False, "name": None, "version": None, "source": "not-detected"}

    slug = theme_match.group(1)
    source = f"/wp-content/themes/{slug}/"
    version = None

    style_url = f"{target.rstrip('/')}/wp-content/themes/{slug}/style.css"
    style = _fetch(style_url, timeout=timeout, proxy=proxy)
    if not is_baseline_match(style, baseline) and style.get("status") == 200:
        body = style.get("body", "")
        match = re.search(r"^\s*Version:\s*([^\r\n<]+)", body, re.IGNORECASE | re.MULTILINE)
        if match:
            version = match.group(1).strip()
            source = f"{source}style.css"

    if not version:
        asset_match = re.search(
            rf"/wp-content/themes/{re.escape(slug)}/[^?\"']+\?ver=([0-9]+(?:\.[0-9]+)*)",
            html,
            re.IGNORECASE,
        )
        if asset_match:
            version = asset_match.group(1)
            source = f"{source}asset-query"

    return {"found": True, "name": slug, "version": version, "source": source}


def detect_wordpress_plugins(
    target: str,
    timeout: int,
    proxy: str | None = None,
    baseline: dict | None = None,
) -> dict:
    home = _fetch(f"{target.rstrip('/')}/", timeout=timeout, proxy=proxy)
    if is_baseline_match(home, baseline):
        return {"plugins": {}, "theme": {"found": False, "name": None, "version": None, "source": "not-detected"}}
    html = home.get("body", "")
    asset_slugs = set(re.findall(r"/wp-content/plugins/([A-Za-z0-9_-]+)/", html, re.IGNORECASE))
    slugs = asset_slugs | set(KNOWN_PLUGIN_MARKERS)

    plugins: dict[str, dict] = {}
    for slug in sorted(slugs):
        version = None
        found = slug in asset_slugs
        source = f"/wp-content/plugins/{slug}/"

        readme = _fetch(f"{target.rstrip('/')}/wp-content/plugins/{slug}/readme.txt", timeout=timeout, proxy=proxy)
        readme_body = readme.get("body", "")
        marker = KNOWN_PLUGIN_MARKERS.get(slug)
        valid_readme = marker is None or bool(re.search(marker, readme_body, re.IGNORECASE))
        if (
            not is_baseline_match(readme, baseline)
            and readme.get("status") == 200
            and len(readme_body) > 20
            and valid_readme
        ):
            found = True
            parsed = parse_wordpress_plugin_version(readme_body)
            if parsed:
                version = parsed
                source = f"{source}readme.txt"

        if not version:
            asset_match = re.search(
                rf"/wp-content/plugins/{re.escape(slug)}/[^?\"']+\?ver=([0-9]+(?:\.[0-9]+)*)",
                html,
                re.IGNORECASE,
            )
            if asset_match:
                version = asset_match.group(1)
                source = f"{source}asset-query"

        if found:
            plugins[slug] = {
                "found": True,
                "version": version,
                "source": source,
            }

    return {
        "plugins": plugins,
        "theme": detect_wordpress_theme(target, html, timeout, proxy=proxy, baseline=baseline),
    }
