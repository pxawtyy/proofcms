from __future__ import annotations

import json
import re
import urllib.parse

from ..core.http import fetch_url, is_baseline_match
from ..core.models import CMSInfo

KNOWN_PLUGIN_MARKERS = {
    "advanced-db-cleaner": r"advanced[-_ ]db[-_ ]cleaner",
    "contact-form-7": r"Contact\s+Form\s+7",
    "cookieyes": r"cookieyes|\bcky[-_/]",
    "drag-and-drop-multiple-file-upload-contact-form-7": r"Drag\s+and\s+Drop\s+Multiple\s+File\s+Upload",
    "essential-addons-for-elementor-lite": r"Essential\s+Addons\s+for\s+Elementor",
    "litespeed-cache": r"LiteSpeed\s+Cache",
    "really-simple-ssl": r"Really\s+Simple\s+(?:SSL|Security)",
    "ultimate-member": r"Ultimate\s+Member",
    "woocommerce-payments": r"Woo(?:Commerce\s+)?Payments|WooPayments",
    "revslider": r"Slider\s+Revolution|Revolution\s+Slider|revslider",
    "wp-file-manager": r"(?:WP\s+)?File\s+Manager",
    "keydatas": r"keydatas|简数",
    "elementor": r"(?:^|/)elementor(?:/|$)|Elementor",
    "google-site-kit": r"google[-_ ]site[-_ ]kit|Site\s+Kit",
    "jetpack": r"Jetpack|my-jetpack|jetpack-boost",
    "popup-maker": r"popup-maker|Popup\s+Maker|pum_vars",
    "wordfence": r"wordfence",
    "webp-converter": r"webp-converter|WebP\s+Converter",
    "wp-accessibility": r"wp-accessibility|WP\s+Accessibility",
    "wp-super-cache": r"wp-super-cache|X-WP-SPC",
    "yoast": r"wordpress-seo|Yoast",
}

REST_NAMESPACE_PLUGINS = {
    "advanced-db-cleaner": "advanced-db-cleaner",
    "cky": "cookieyes",
    "cookieyes": "cookieyes",
    "ea11y": "pojo-accessibility",
    "elementor-ai": "elementor-ai",
    "elementor-mcp-composer": "elementor-mcp-composer",
    "elementor-one": "elementor-one",
    "elementor": "elementor",
    "google-site-kit": "google-site-kit",
    "jetpack": "jetpack",
    "jetpack-boost": "jetpack",
    "my-jetpack": "jetpack",
    "popup-maker": "popup-maker",
    "pum": "popup-maker",
    "spc": "wp-super-cache",
    "wordfence-login-security": "wordfence-login-security",
    "wordfence": "wordfence",
    "webp-converter": "webp-converter",
    "wpcom": "jetpack",
    "yoast": "yoast",
}


def _fetch(url: str, timeout: int, proxy: str | None = None) -> dict:
    return fetch_url(url, timeout=timeout, proxy=proxy)


def _declares_non_wordpress_platform(response: dict) -> bool:
    """Recognize authoritative Java/DSpace signals before considering WP-shaped assets."""
    body = str(response.get("body", ""))
    headers = response.get("headers") or {}
    header_text = "\n".join(f"{key}: {value}" for key, value in headers.items())
    combined = f"{header_text}\n{body}"
    return bool(
        re.search(
            r'<meta\s+name=["\']generator["\']\s+content=["\']DSpace\b|'
            r"\bX-Cocoon-Version\s*:|\bApache Tomcat/|\bJSESSIONID\b|;jsessionid=",
            combined,
            re.IGNORECASE,
        )
    )


def _installation_base(target: str, response: dict, requested_path: str) -> str:
    final_url = str(response.get("final_url") or "")
    if not final_url:
        return target.rstrip("/")
    parsed = urllib.parse.urlsplit(final_url)
    final_path = parsed.path or "/"
    if requested_path == "/":
        base_path = final_path.rstrip("/")
    elif final_path.lower().endswith(requested_path.lower()):
        base_path = final_path[: -len(requested_path)].rstrip("/")
    else:
        return target.rstrip("/")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, base_path, "", ""))


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
        r"https?://c[0-9]+\.wp\.com/c/([0-9]+(?:\.[0-9]+){1,3})/",
        r"<br\s*/?>\s*Version\s+([0-9]+(?:\.[0-9]+){1,3})",
    ]
    best: CMSInfo | None = None
    for path in paths:
        response = _fetch(f"{target.rstrip('/')}{path}", timeout=timeout, proxy=proxy)
        if path == "/" and _declares_non_wordpress_platform(response):
            return CMSInfo("wordpress", False, None, "wordpress:vetoed-by-platform", "")
        if is_baseline_match(response, baseline):
            continue
        status = response.get("status", 0)
        body = response.get("body", "")
        lowered = body.lower()
        source = f"wordpress:{path}"
        base_url = _installation_base(target, response, path)

        version = None
        patterns = version_patterns if path in {"/", "/readme.html"} else version_patterns[:3]
        for pattern in patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                version = match.group(1).strip()
                break

        has_wp_signature = bool(
            "wp-content/" in lowered
            or "wp-includes/" in lowered
            or re.search(r"wordpress|wp-json|wp-login|wp-admin", body, re.IGNORECASE)
        )
        if status == 200 and version and has_wp_signature:
            return CMSInfo("wordpress", True, version, source, body[:2000], base_url)

        if path == "/wp-json/" and status == 200 and re.search(r'"namespaces"\s*:|wp/v2|wp-site-health', body, re.IGNORECASE):
            best = best or CMSInfo("wordpress", True, None, source, body[:2000], base_url)
            continue

        if path == "/wp-login.php" and status in (200, 302) and re.search(r"wp-login|wordpress|loginform", body, re.IGNORECASE):
            best = best or CMSInfo("wordpress", True, None, source, body[:2000], base_url)
            continue

        if path == "/wp-admin/" and status in (200, 302) and re.search(r"wp-admin|wordpress|wp-login", body, re.IGNORECASE):
            best = best or CMSInfo("wordpress", True, None, source, body[:2000], base_url)
            continue

        if path == "/" and (
            "wp-content/" in lowered
            or "wp-includes/" in lowered
            or re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress', body, re.IGNORECASE)
        ):
            best = best or CMSInfo("wordpress", True, None, source, body[:2000], base_url)

    return best or CMSInfo("wordpress", False, None, "wordpress:fallback", "")


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
            source = f"{source}asset-query-tentative"

    return {"found": True, "name": slug, "version": version, "source": source}


def detect_wordpress_plugins(
    target: str,
    timeout: int,
    proxy: str | None = None,
    baseline: dict | None = None,
) -> dict:
    home = _fetch(f"{target.rstrip('/')}/", timeout=timeout, proxy=proxy)
    if home.get("status", 0) == 0:
        return {
            "plugins": {},
            "theme": {"found": False, "name": None, "version": None, "source": "error"},
            "errors": [home.get("error") or {"type": "TransportError", "message": "homepage request failed"}],
        }
    if is_baseline_match(home, baseline):
        return {"plugins": {}, "theme": {"found": False, "name": None, "version": None, "source": "not-detected"}}
    html = home.get("body", "")
    asset_slugs = set(re.findall(r"/wp-content/plugins/([A-Za-z0-9_-]+)/", html, re.IGNORECASE))
    rest_plugins: dict[str, str] = {}
    rest = _fetch(f"{target.rstrip('/')}/wp-json/", timeout=timeout, proxy=proxy)
    if rest.get("status") == 200 and not is_baseline_match(rest, baseline):
        try:
            payload = json.loads(rest.get("body", ""))
        except (json.JSONDecodeError, TypeError):
            payload = {}
        namespaces = payload.get("namespaces", []) if isinstance(payload, dict) else []
        for namespace in namespaces if isinstance(namespaces, list) else []:
            root = str(namespace).split("/", 1)[0].lower()
            slug = REST_NAMESPACE_PLUGINS.get(root)
            if slug:
                rest_plugins.setdefault(slug, str(namespace))
    slugs = asset_slugs | set(KNOWN_PLUGIN_MARKERS) | set(rest_plugins)

    plugins: dict[str, dict] = {}
    for slug in sorted(slugs):
        version = None
        found = slug in asset_slugs or slug in rest_plugins
        source = f"/wp-content/plugins/{slug}/"
        if slug in rest_plugins and slug not in asset_slugs:
            source = f"/wp-json/:{rest_plugins[slug]}"

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

        if slug == "popup-maker" and not version:
            popup_version = re.search(
                r"\bpum_vars\s*=\s*\{.*?[\"']version[\"']\s*:\s*[\"']([^\"']+)",
                html,
                re.IGNORECASE | re.DOTALL,
            )
            if popup_version:
                version = popup_version.group(1).strip()
                source = "/:pum_vars"

        if found:
            plugins[slug] = {
                "found": True,
                "version": version,
                "source": source,
                "version_confidence": "LOW" if "asset-query" in source else "HIGH",
            }

    return {
        "plugins": plugins,
        "theme": detect_wordpress_theme(target, html, timeout, proxy=proxy, baseline=baseline),
        "errors": [],
    }
