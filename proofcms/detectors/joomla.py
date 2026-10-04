from __future__ import annotations

import re
from typing import Any

from ..core.http import fetch_url, is_baseline_match
from ..core.models import JoomlaInfo, PluginInfo


def _valid_extension_manifest(response: dict, marker_pattern: str) -> bool:
    """Reject HTML fake-200 pages masquerading as public extension manifests."""
    if response.get("status") != 200:
        return False
    body = response.get("body", "")
    content_type = str(response.get("content_type", "")).lower()
    if "text/html" in content_type:
        return False
    return bool(
        re.search(r"<(?:extension|install)\b", body, re.IGNORECASE)
        and re.search(r"<version>\s*[^<\s]+\s*</version>", body, re.IGNORECASE)
        and re.search(marker_pattern, body, re.IGNORECASE)
    )


def _without_request_reflections(body: str, target: str, path: str) -> str:
    """Remove echoed request URLs before applying component marker regexes."""
    variants = {
        path,
        path.replace("&", "&amp;"),
        f"{target.rstrip('/')}{path}",
        f"{target.rstrip('/')}{path}".replace("&", "&amp;"),
    }
    cleaned = body
    for value in sorted(variants, key=len, reverse=True):
        cleaned = cleaned.replace(value, "")
    return cleaned


def validate_joomla_manifest(body: str, path: str) -> bool:
    """
    Validates that an XML file or README.txt actually belongs to an authentic Joomla installation.
    Prevents false positives from non-Joomla sites responding 200 with arbitrary XML.
    """
    if path == "/README.txt":
        # Require institutional signature from Open Source Matters / Joomla! CMS / GPL
        institutional_pattern = (
            r"(?:Open\s+Source\s+Matters|GNU\s+(?:General\s+Public\s+License|GPL)|"
            r"https?://(?:www\.)?joomla\.org|Joomla!\s+(?:CMS|Project))"
        )
        has_institutional = bool(re.search(institutional_pattern, body, re.IGNORECASE))
        return has_institutional and bool(re.search(r"\bJoomla!?\b", body, re.IGNORECASE))

    if not path.endswith(".xml"):
        return True

    # Must have XML declaration or recognizable root extension/metafile/install tag
    if not re.search(r"<\?xml|<extension|<metafile|<install", body, re.IGNORECASE):
        return False
    if not re.search(r"<(?:extension|metafile|install)\b[^>]*>", body, re.IGNORECASE):
        return False
    if not re.search(r"<version>\s*[^<\s]+\s*</version>", body, re.IGNORECASE):
        return False

    # Route-specific validation
    if path == "/administrator/manifests/files/joomla.xml":
        # Must have name files_joomla or joomla, type="file", and Joomla Project author
        valid_name = bool(re.search(r"<name>\s*(?:files_)?joomla\s*</name>", body, re.IGNORECASE))
        valid_type = bool(re.search(r'type=["\']file["\']', body, re.IGNORECASE))
        valid_author = bool(re.search(r"<author>\s*Joomla!?\s*(?:Project)?\s*</author>", body, re.IGNORECASE))
        return valid_name and (valid_type or valid_author)

    if path == "/language/en-GB/en-GB.xml":
        valid_name = bool(re.search(r"<name>\s*(?:English\s*\(en-GB\)|en-GB)\s*</name>", body, re.IGNORECASE))
        valid_tag = bool(re.search(r"<tag>\s*en-GB\s*</tag>", body, re.IGNORECASE))
        client_pattern = (
            r'client=["\'](?:site|administrator)["\']|'
            r"<client>\s*(?:site|administrator)\s*</client>"
        )
        valid_client = bool(re.search(client_pattern, body, re.IGNORECASE))
        return (valid_name or valid_tag) and valid_client

    if path == "/administrator/components/com_content/content.xml":
        valid_name = bool(re.search(r"<name>\s*(?:com_content|content)\s*</name>", body, re.IGNORECASE))
        valid_type = bool(re.search(r'type=["\']component["\']', body, re.IGNORECASE))
        valid_author = bool(re.search(r"<author>\s*Joomla!?\s*(?:Project)?\s*</author>", body, re.IGNORECASE))
        return valid_name and (valid_type or valid_author)

    if path == "/administrator/components/com_media/media.xml":
        valid_name = bool(re.search(r"<name>\s*(?:com_media|media)\s*</name>", body, re.IGNORECASE))
        valid_type = bool(re.search(r'type=["\']component["\']', body, re.IGNORECASE))
        valid_author = bool(re.search(r"<author>\s*Joomla!?\s*(?:Project)?\s*</author>", body, re.IGNORECASE))
        return valid_name and (valid_type or valid_author)

    # Generic Joomla extension manifest fallback (must validate name, type, and author)
    has_joomla_author = bool(re.search(r"<author>\s*Joomla!?\s*(?:Project)?\s*</author>", body, re.IGNORECASE))
    has_joomla_name = bool(re.search(r"<name>\s*(?:files_)?joomla\s*</name>", body, re.IGNORECASE))
    has_valid_type = bool(
        re.search(r'type=["\'](?:file|component|plugin|module|package|language)["\']', body, re.IGNORECASE)
    )
    return (has_joomla_name or has_joomla_author) and has_valid_type


def scan_joomla(
    target: str,
    timeout: int,
    proxy: str | None = None,
    baseline: dict | None = None,
) -> JoomlaInfo:
    """Fingerprint Joomla and its version using native, proxy-aware HTTP probes."""
    paths = [
        "/administrator/manifests/files/joomla.xml",
        "/language/en-GB/en-GB.xml",
        "/administrator/components/com_content/content.xml",
        "/administrator/components/com_media/media.xml",
        "/README.txt",
        "/",
    ]
    for path in paths:
        url = f"{target.rstrip('/')}{path}"
        response = fetch_url(url, timeout=timeout, proxy=proxy)
        if is_baseline_match(response, baseline):
            continue
        if response.get("status") != 200:
            continue
        body = response.get("body", "")

        if path.endswith(".xml"):
            if not validate_joomla_manifest(body, path):
                continue
            version_match = re.search(r"<version>\s*([^<\s]+)\s*</version>", body, re.IGNORECASE)
            if version_match:
                return JoomlaInfo(True, version_match.group(1), f"native:{path}", body[:2000])

        elif path == "/README.txt":
            if not validate_joomla_manifest(body, path):
                continue
            readme_match = re.search(r"\bJoomla!?\s+([0-9]+(?:\.[0-9]+)+)", body, re.IGNORECASE)
            if readme_match:
                return JoomlaInfo(True, readme_match.group(1), f"native:{path}", body[:2000])
            if "joomla" in body.lower():
                return JoomlaInfo(True, None, f"native:{path}", body[:2000])

        elif path == "/":
            meta_match = re.search(
                r'<meta\s+name=["\']generator["\']\s+content=["\']Joomla!?\s*([0-9.]+)',
                body,
                re.IGNORECASE,
            )
            if meta_match:
                return JoomlaInfo(True, meta_match.group(1), f"native:{path}", body[:2000])
            if re.search(r"/templates/|/media/system/|csrf\.token|Joomla!", body, re.IGNORECASE):
                return JoomlaInfo(True, None, f"native:{path}", body[:2000])

    return JoomlaInfo(False, None, "native", "")


def detect_joomla(target: str, args, baseline: dict | None = None) -> JoomlaInfo:
    """Detects whether target is running Joomla and its version."""
    info = scan_joomla(target, args.timeout, proxy=args.proxy, baseline=baseline)
    if info.detected:
        return info
    return JoomlaInfo(False, None, "not-detected", "")


def joomla_signal_score(info: JoomlaInfo) -> int:
    if not info.detected:
        return 0
    score = 1
    if info.version:
        score += 3
    if info.source.startswith("native:/administrator/manifests/files/joomla.xml"):
        score += 3
    if info.source.startswith("native:/") and info.source.endswith(".xml"):
        score += 2
    if re.search(r"joomla|com_content|administrator/templates|csrf\.token", info.raw or "", re.IGNORECASE):
        score += 1
    return score


def detect_icagenda(
    target: str,
    timeout: int,
    proxy: str | None = None,
    baseline: dict | None = None,
) -> PluginInfo:
    paths = [
        "/administrator/components/com_icagenda/icagenda.xml",
        "/administrator/components/com_icagenda/com_icagenda.xml",
        "/components/com_icagenda/icagenda.xml",
        "/index.php?option=com_icagenda",
        "/component/icagenda/",
        "/components/com_icagenda/",
        "/media/com_icagenda/",
    ]
    version_patterns = [
        r"iCagenda\s+CORE\s+([0-9]+(?:\.[0-9]+)+)",
        r"iCagenda[^0-9]{0,40}([0-9]+(?:\.[0-9]+)+)",
        r"com_icagenda[^0-9]{0,40}([0-9]+(?:\.[0-9]+)+)",
    ]
    for path in paths:
        url = f"{target.rstrip('/')}{path}"
        response = fetch_url(url, timeout=timeout, proxy=proxy)
        if is_baseline_match(response, baseline):
            continue
        body = response.get("body", "")
        if (
            path.endswith(".xml")
            and _valid_extension_manifest(response, r"icagenda|com_icagenda")
        ):
            version = None
            version_match = re.search(r"<version>\s*([^<\s]+)\s*</version>", body, re.IGNORECASE)
            if version_match:
                version = version_match.group(1)
            return PluginInfo(True, version, path)
        if response["status"] == 200 and re.search(r"icagenda|com_icagenda|joomlic", body, re.IGNORECASE):
            version = None
            for pattern in version_patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    break
            return PluginInfo(True, version, path)
        if (
            response["status"] == 403
            and path in ("/components/com_icagenda/", "/media/com_icagenda/")
            and not (baseline and baseline.get("blanket_403"))
        ):
            return PluginInfo(True, None, f"{path} ({response['status']})")
    return PluginInfo(False, None, "not-detected")


def detect_baforms(
    target: str,
    timeout: int,
    proxy: str | None = None,
    baseline: dict | None = None,
) -> PluginInfo:
    manifest_paths = [
        "/administrator/components/com_baforms/baforms.xml",
        "/components/com_baforms/baforms.xml",
    ]
    for path in manifest_paths:
        url = f"{target.rstrip('/')}{path}"
        response = fetch_url(url, timeout=timeout, proxy=proxy)
        if is_baseline_match(response, baseline):
            continue
        body = response.get("body", "")
        if _valid_extension_manifest(response, r"baforms|balbooa"):
            match = re.search(r"<version>\s*([^<\s]+)\s*</version>", body, re.IGNORECASE)
            version = match.group(1).strip() if match else None
            return PluginInfo(True, version, path)

    checks = [
        ("/images/baforms/uploads/", "uploads"),
        ("/component/baforms", "component"),
    ]
    version_patterns = [
        r"Balbooa\s+Forms[^0-9]{0,40}([0-9]+(?:\.[0-9]+)+)",
        r"baforms[^0-9]{0,40}([0-9]+(?:\.[0-9]+)+)",
        r"com_baforms[^0-9]{0,40}([0-9]+(?:\.[0-9]+)+)",
    ]
    for path, source in checks:
        url = f"{target.rstrip('/')}{path}"
        response = fetch_url(url, timeout=timeout, proxy=proxy)
        if is_baseline_match(response, baseline):
            continue
        body = response.get("body", "")
        if source == "uploads":
            has_specific_marker = bool(re.search(r"baforms|balbooa", body, re.IGNORECASE))
            if response["status"] == 403 and has_specific_marker:
                return PluginInfo(True, None, f"{path} (403-public-exec-blocked)")
            if response["status"] == 200 and has_specific_marker:
                return PluginInfo(True, None, f"{path} (200-uploads-open)")
            continue
        if response["status"] == 200 and re.search(r"baforms|balbooa", body, re.IGNORECASE):
            version = None
            for pattern in version_patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    break
            return PluginInfo(True, version, path)

    return PluginInfo(False, None, "not-detected")


def detect_sppagebuilder(
    target: str,
    timeout: int,
    proxy: str | None = None,
    baseline: dict | None = None,
) -> PluginInfo:
    paths = [
        "/component/sppagebuilder/",
        "/index.php?option=com_sppagebuilder",
    ]
    version_patterns = [
        r"SP\s*Page\s*Builder[^0-9]{0,40}([0-9]+(?:\.[0-9]+)+)",
        r"sppagebuilder[^0-9]{0,40}([0-9]+(?:\.[0-9]+)+)",
        r"com_sppagebuilder[^0-9]{0,40}([0-9]+(?:\.[0-9]+)+)",
    ]
    for path in paths:
        url = f"{target.rstrip('/')}{path}"
        response = fetch_url(url, timeout=timeout, proxy=proxy)
        if is_baseline_match(response, baseline):
            continue
        body = response.get("body", "")
        if (
            _valid_extension_manifest(response, r"sppagebuilder|sp page builder|com_sppagebuilder")
        ):
            version = None
            for pattern in version_patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    break
            return PluginInfo(True, version, path)

    manifest_paths = [
        "/administrator/components/com_sppagebuilder/sppagebuilder.xml",
        "/components/com_sppagebuilder/sppagebuilder.xml",
        "/administrator/components/com_sppagebuilder/com_sppagebuilder.xml",
    ]
    for path in manifest_paths:
        url = f"{target.rstrip('/')}{path}"
        response = fetch_url(url, timeout=timeout, proxy=proxy)
        if is_baseline_match(response, baseline):
            continue
        body = response.get("body", "")
        if (
            response["status"] == 200
            and re.search(r"sppagebuilder|sp page builder|com_sppagebuilder", body, re.IGNORECASE)
        ):
            match = re.search(r"<version>\s*([^<\s]+)\s*</version>", body, re.IGNORECASE)
            return PluginInfo(True, match.group(1).strip() if match else None, path)
    return PluginInfo(False, None, "not-detected")


def detect_pagebuilderck(
    target: str,
    timeout: int,
    proxy: str | None = None,
    baseline: dict | None = None,
) -> PluginInfo:
    manifest_paths = [
        "/administrator/components/com_pagebuilderck/pagebuilderck.xml",
        "/components/com_pagebuilderck/pagebuilderck.xml",
        "/administrator/components/com_pagebuilderck/com_pagebuilderck.xml",
    ]
    for path in manifest_paths:
        url = f"{target.rstrip('/')}{path}"
        response = fetch_url(url, timeout=timeout, proxy=proxy)
        if is_baseline_match(response, baseline):
            continue
        body = response.get("body", "")
        if _valid_extension_manifest(response, r"pagebuilderck|Page\s*Builder\s*CK"):
            match = re.search(r"<version>\s*([^<\s]+)\s*</version>", body, re.IGNORECASE)
            return PluginInfo(True, match.group(1).strip() if match else None, path)

    paths = [
        "/components/com_pagebuilderck/",
        "/component/pagebuilderck/",
        "/media/com_pagebuilderck/",
        "/index.php?option=com_pagebuilderck",
    ]
    version_patterns = [
        r"pagebuilderck[/\"'\s_-]*(?:v|version)?[^0-9]{0,20}([0-9]+(?:\.[0-9]+)+)",
        r"com_pagebuilderck[^0-9]{0,40}([0-9]+(?:\.[0-9]+)+)",
        r"Page\s*Builder\s*CK[^0-9]{0,40}([0-9]+(?:\.[0-9]+)+)",
    ]
    for path in paths:
        url = f"{target.rstrip('/')}{path}"
        response = fetch_url(url, timeout=timeout, proxy=proxy)
        if is_baseline_match(response, baseline):
            continue
        body = response.get("body", "")
        if response["status"] == 403 and path.startswith(("/components/", "/media/")):
            if baseline and baseline.get("blanket_403"):
                continue
            version = None
            for pattern in version_patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    break
            if version or re.search(r"pagebuilderck|com_pagebuilderck", body, re.IGNORECASE):
                return PluginInfo(True, version, f"{path} (403)")
            continue
        if (
            response["status"] == 200
            and re.search(r"pagebuilderck|com_pagebuilderck|Page\s*Builder\s*CK", body, re.IGNORECASE)
        ):
            version = None
            for pattern in version_patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    break
            return PluginInfo(True, version, path)

    return PluginInfo(False, None, "not-detected")


def detect_rsfiles(
    target: str,
    timeout: int,
    proxy: str | None = None,
    baseline: dict | None = None,
) -> PluginInfo:
    paths = [
        "/components/com_rsfiles/",
        "/component/rsfiles/",
        "/index.php?option=com_rsfiles",
        "/media/com_rsfiles/css/rsfiles.css",
    ]
    version_patterns = [
        r"RSFiles!?[^0-9]{0,40}([0-9]+(?:\.[0-9]+)+)",
        r"com_rsfiles[^0-9]{0,40}([0-9]+(?:\.[0-9]+)+)",
        r"rsfiles[^0-9]{0,40}([0-9]+(?:\.[0-9]+)+)",
    ]
    fallback = PluginInfo(False, None, "not-detected")
    for path in paths:
        url = f"{target.rstrip('/')}{path}"
        response = fetch_url(url, timeout=timeout, proxy=proxy)
        if is_baseline_match(response, baseline):
            continue
        body = response.get("body", "")
        if re.search(r"<title>\s*Index of\s+/components/com_rsfiles/?\s*</title>", body, re.IGNORECASE):
            continue
        if (
            response["status"] == 403
            and "com_rsfiles" in path
            and not (baseline and baseline.get("blanket_403"))
            and re.search(r"rsfiles|com_rsfiles", body, re.IGNORECASE)
        ):
            fallback = PluginInfo(True, None, f"{path} (403)")
            continue
        if _valid_extension_manifest(response, r"rsfiles|com_rsfiles"):
            version = None
            for pattern in version_patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    break
            return PluginInfo(True, version, path)

    manifest_paths = [
        "/administrator/components/com_rsfiles/rsfiles.xml",
        "/components/com_rsfiles/rsfiles.xml",
    ]
    for path in manifest_paths:
        url = f"{target.rstrip('/')}{path}"
        response = fetch_url(url, timeout=timeout, proxy=proxy)
        if is_baseline_match(response, baseline):
            continue
        body = response.get("body", "")
        if response["status"] == 200 and re.search(r"rsfiles|com_rsfiles", body, re.IGNORECASE):
            match = re.search(r"<version>\s*([^<\s]+)\s*</version>", body, re.IGNORECASE)
            return PluginInfo(True, match.group(1).strip() if match else None, path)
    return fallback


def detect_helix3(
    target: str,
    timeout: int,
    proxy: str | None = None,
    baseline: dict | None = None,
) -> PluginInfo:
    manifest_paths = [
        "/templates/shaper_helix3/templateDetails.xml",
        "/plugins/system/helix3/helix3.xml",
        "/plugins/ajax/helix3/helix3.xml",
    ]
    html_paths = [
        "/",
        "/index.php?option=com_ajax&plugin=helix3&format=json",
    ]
    version_patterns = [
        r"<version>\s*([^<\s]+)\s*</version>",
        r"Helix3?[^0-9]{0,40}([0-9]+(?:\.[0-9]+)+)",
        r"shaper_helix3[^0-9]{0,40}([0-9]+(?:\.[0-9]+)+)",
    ]

    fallback = PluginInfo(False, None, "not-detected")
    for path in manifest_paths:
        url = f"{target.rstrip('/')}{path}"
        response = fetch_url(url, timeout=timeout, proxy=proxy)
        if is_baseline_match(response, baseline):
            continue
        body = response.get("body", "")
        if (
            response["status"] == 403
            and "helix3" in path.lower()
            and not (baseline and baseline.get("blanket_403"))
            and re.search(r"helix3|shaper_helix3", body, re.IGNORECASE)
        ):
            fallback = PluginInfo(True, None, f"{path} (403)")
            continue
        if _valid_extension_manifest(response, r"helix3|shaper_helix3|JoomShaper"):
            version = None
            for pattern in version_patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    version = match.group(1).strip()
                    break
            return PluginInfo(True, version, path)

    for path in html_paths:
        url = f"{target.rstrip('/')}{path}"
        response = fetch_url(url, timeout=timeout, proxy=proxy)
        if is_baseline_match(response, baseline):
            continue
        body = response.get("body", "")
        if (
            response["status"] == 200
            and "plugin=helix3" in path
            and re.search(r"helix3|shaper_helix3|JoomShaper", body, re.IGNORECASE)
        ):
            return PluginInfo(True, None, path)
        if (
            response["status"] == 200
            and re.search(r"helix3|shaper_helix3|templates/shaper_helix3", body, re.IGNORECASE)
        ):
            version = None
            for pattern in version_patterns[1:]:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    version = match.group(1).strip()
                    break
            return PluginInfo(True, version, path)
    return fallback


def detect_helixultimate(
    target: str,
    timeout: int,
    proxy: str | None = None,
    baseline: dict | None = None,
) -> PluginInfo:
    paths = [
        "/templates/shaper_helixultimate/",
        "/templates/shaper_helixultimate/css/",
        "/templates/shaper_helixultimate/js/",
        "/plugins/system/helixultimate/",
        "/plugins/system/helixultimate/src/",
        "/plugins/system/helixultimate/src/Platform/",
    ]
    manifest_paths = [
        "/templates/shaper_helixultimate/templateDetails.xml",
        "/plugins/system/helixultimate/helixultimate.xml",
        "/plugins/system/helixultimate/helixultimate.php",
    ]
    version_patterns = [
        r"<version>\s*([^<\s]+)\s*</version>",
        r"Helix\s*Ultimate[^0-9]{0,40}([0-9]+(?:\.[0-9]+)+)",
        r"helixultimate[^0-9]{0,40}([0-9]+(?:\.[0-9]+)+)",
        r"shaper_helixultimate[^0-9]{0,40}([0-9]+(?:\.[0-9]+)+)",
    ]
    fallback = PluginInfo(False, None, "not-detected")

    for path in manifest_paths:
        url = f"{target.rstrip('/')}{path}"
        response = fetch_url(url, timeout=timeout, proxy=proxy)
        if is_baseline_match(response, baseline):
            continue
        body = response.get("body", "")
        if (
            response["status"] == 403
            and "helixultimate" in path.lower()
            and not (baseline and baseline.get("blanket_403"))
            and re.search(r"helixultimate|shaper_helixultimate", body, re.IGNORECASE)
        ):
            fallback = PluginInfo(True, None, f"{path} (403)")
            continue
        manifest_valid = (
            _valid_extension_manifest(response, r"helixultimate|shaper_helixultimate|Helix\s*Ultimate")
            if path.endswith(".xml")
            else response["status"] == 200
            and re.search(r"helixultimate|shaper_helixultimate|Helix\s*Ultimate", body, re.IGNORECASE)
        )
        if manifest_valid:
            version = None
            for pattern in version_patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    version = match.group(1).strip()
                    break
            return PluginInfo(True, version, path)

    for path in paths:
        url = f"{target.rstrip('/')}{path}"
        response = fetch_url(url, timeout=timeout, proxy=proxy)
        if is_baseline_match(response, baseline):
            continue
        body = response.get("body", "")
        if (
            response["status"] == 403
            and ("helixultimate" in path.lower() or "shaper_helixultimate" in path.lower())
            and not (baseline and baseline.get("blanket_403"))
            and re.search(r"helixultimate|shaper_helixultimate", body, re.IGNORECASE)
        ):
            fallback = PluginInfo(True, None, f"{path} (403)")
            continue
        if (
            response["status"] == 200
            and re.search(r"helixultimate|shaper_helixultimate|Helix\s*Ultimate", body, re.IGNORECASE)
        ):
            version = None
            for pattern in version_patterns[1:]:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    version = match.group(1).strip()
                    break
            return PluginInfo(True, version, path)
    return fallback


COMMON_COMPONENTS: dict[str, dict[str, Any]] = {
    "articles_good_search": {
        "manifests": ["/modules/mod_articles_good_search/mod_articles_good_search.xml"],
        "routes": [],
        "markers": r"mod_articles_good_search|Articles\s+Good\s+Search",
    },
    "akeebabackup": {
        "manifests": [
            "/administrator/components/com_akeebabackup/akeebabackup.xml",
            "/administrator/components/com_akeeba/akeeba.xml",
        ],
        "routes": ["/?option=com_akeebabackup", "/?option=com_akeeba"],
        "markers": r"com_akeebabackup|com_akeeba|Akeeba\s+Backup",
    },
    "jsitemap": {
        "manifests": ["/administrator/components/com_jsitemap/jsitemap.xml"],
        "routes": ["/?option=com_jsitemap"],
        "markers": r"com_jsitemap|JSitemap",
    },
    "jce": {
        "manifests": [
            "/administrator/components/com_jce/jce.xml",
            "/plugins/system/jce/jce.xml",
            "/plugins/editors/jce/jce.xml",
        ],
        "routes": ["/?option=com_jce"],
        "markers": r"com_jce|JCE\s+(?:Editor|Administration|Component)",
    },
    "convertforms": {
        "manifests": [
            "/administrator/components/com_convertforms/convertforms.xml",
            "/plugins/system/convertforms/convertforms.xml",
        ],
        "routes": ["/?option=com_convertforms"],
        "markers": r"com_convertforms|Convert\s+Forms",
    },
    "nrframework": {
        "manifests": ["/plugins/system/nrframework/nrframework.xml"],
        "routes": [],
        "markers": r"(?:plg_system_)?nrframework|NovaRain|Tassos\s+Framework",
    },
    "google_structured_data": {
        "manifests": [
            "/administrator/components/com_gsd/gsd.xml",
            "/plugins/system/gsd/gsd.xml",
        ],
        "routes": ["/?option=com_gsd"],
        "markers": r"com_gsd|Google\s+Structured\s+Data",
    },
    "advanced_custom_fields": {
        "manifests": [
            "/administrator/components/com_acf/acf.xml",
            "/plugins/system/acf/acf.xml",
            "/plugins/fields/acf/acf.xml",
        ],
        "routes": ["/?option=com_acf"],
        "markers": r"com_acf|Advanced\s+Custom\s+Fields|(?:plg_)?(?:system|fields)_acf",
    },
    "smilepack": {
        "manifests": ["/administrator/components/com_smilepack/smilepack.xml"],
        "routes": ["/?option=com_smilepack"],
        "markers": r"com_smilepack|Smile\s+Pack",
    },
    "mailchimp_auto_subscribe": {
        "manifests": [
            "/plugins/system/nr_mailchimp/nr_mailchimp.xml",
            "/plugins/user/nr_mailchimp/nr_mailchimp.xml",
            "/plugins/system/mailchimpautosubscribe/mailchimpautosubscribe.xml",
        ],
        "routes": [],
        "markers": r"nr_mailchimp|mailchimpautosubscribe|MailChimp\s+Auto-Subscribe",
    },
    "rsform": {
        "manifests": [
            "/administrator/components/com_rsform/rsform.xml",
            "/administrator/components/com_rsform/rsformpro.xml",
        ],
        "routes": ["/?option=com_rsform"],
        "markers": r"com_rsform|RSForm!?\s*Pro",
    },
    "eventbooking": {
        "manifests": ["/administrator/components/com_eventbooking/eventbooking.xml"],
        "routes": ["/?option=com_eventbooking"],
        "markers": r"com_eventbooking|Event\s+Booking",
    },
    "engagebox": {
        "manifests": [
            "/administrator/components/com_rstbox/rstbox.xml",
            "/administrator/components/com_engagebox/engagebox.xml",
            "/plugins/system/rstbox/rstbox.xml",
            "/plugins/engagebox/engagebox.xml",
        ],
        "routes": ["/?option=com_rstbox", "/?option=com_engagebox"],
        "markers": r"com_rstbox|com_engagebox|EngageBox",
    },
    "djclassifieds": {
        "manifests": ["/administrator/components/com_djclassifieds/djclassifieds.xml"],
        "routes": ["/?option=com_djclassifieds"],
        "markers": r"com_djclassifieds|DJ-?Classifieds",
    },
    "acymailing": {
        "manifests": [
            "/administrator/components/com_acymailing/acymailing.xml",
            "/administrator/components/com_acym/acym.xml",
            "/components/com_acymailing/acymailing.xml",
            "/components/com_acym/acym.xml",
        ],
        "routes": ["/?option=com_acymailing", "/?option=com_acym"],
        "markers": r"com_acymailing|com_acym|AcyMailing",
    },
    "akeeba_update_check": {
        "manifests": ["/plugins/system/akeebaupdatecheck/akeebaupdatecheck.xml"],
        "routes": [],
        "markers": r"akeebaupdatecheck|Akeeba\s+Update\s+Check",
    },
    "backup_on_update": {
        "manifests": ["/plugins/system/backuponupdate/backuponupdate.xml"],
        "routes": [],
        "markers": r"backuponupdate|Backup\s+on\s+Update",
    },
    "convertforms_uploaded_files_cleaner": {
        "manifests": ["/plugins/system/cfuploadedfilescleaner/cfuploadedfilescleaner.xml"],
        "routes": [],
        "markers": r"cfuploadedfilescleaner|Convert\s+Forms.*Uploaded\s+Files\s+Cleaner",
    },
    "convertforms_tools": {
        "manifests": [
            "/plugins/convertformstools/convertformstools.xml",
            "/plugins/convertformstools/tools/tools.xml",
        ],
        "routes": [],
        "markers": r"convertformstools|Convert\s+Forms\s+Tools",
    },
    "dropfiles": {
        "manifests": [
            "/plugins/system/dropfiles/dropfiles.xml",
            "/administrator/components/com_dropfiles/dropfiles.xml",
        ],
        "routes": ["/?option=com_dropfiles"],
        "markers": r"com_dropfiles|plg_system_dropfiles|Dropfiles",
    },
    "dropfiles_themes": {
        "manifests": ["/plugins/dropfilesthemes/dropfilesthemes.xml"],
        "routes": [],
        "markers": r"dropfilesthemes|Dropfiles\s+Themes",
    },
    "k2": {
        "manifests": [
            "/administrator/components/com_k2/k2.xml",
            "/plugins/system/k2/k2.xml",
        ],
        "routes": ["/?option=com_k2"],
        "markers": r"com_k2|plg_system_k2|K2(?:\s+Component)?",
    },
    "login_popup": {
        "manifests": ["/plugins/system/loginpopup/loginpopup.xml"],
        "routes": [],
        "markers": r"loginpopup|Login\s+Popup",
    },
    "rsform_delete_submissions": {
        "manifests": ["/plugins/system/rsformdeletesubmissions/rsformdeletesubmissions.xml"],
        "routes": [],
        "markers": r"rsformdeletesubmissions|RSForm.*Delete\s+Submissions",
    },
    "rsfp_campaignmonitor": {
        "manifests": ["/plugins/system/rsfpcampaignmonitor/rsfpcampaignmonitor.xml"],
        "routes": [],
        "markers": r"rsfpcampaignmonitor|RSForm.*Campaign\s+Monitor",
    },
    "rsfp_google": {
        "manifests": ["/plugins/system/rsfpgoogle/rsfpgoogle.xml"],
        "routes": [],
        "markers": r"rsfpgoogle|RSForm.*Google",
    },
    "rsfp_google_calendar": {
        "manifests": ["/plugins/system/rsfpgooglecalendar/rsfpgooglecalendar.xml"],
        "routes": [],
        "markers": r"rsfpgooglecalendar|RSForm.*Google\s+Calendar",
    },
    "rsfp_google_sheets": {
        "manifests": ["/plugins/system/rsfpgooglesheets/rsfpgooglesheets.xml"],
        "routes": [],
        "markers": r"rsfpgooglesheets|RSForm.*Google\s+Sheets",
    },
    "rsfp_hcaptcha": {
        "manifests": ["/plugins/system/rsfphcaptcha/rsfphcaptcha.xml"],
        "routes": [],
        "markers": r"rsfphcaptcha|RSForm.*hCaptcha",
    },
    "rsfp_ideal": {
        "manifests": ["/plugins/system/rsfpideal/rsfpideal.xml"],
        "routes": [],
        "markers": r"rsfpideal|RSForm.*iDEAL",
    },
    "rsfp_legacy_layouts": {
        "manifests": ["/plugins/system/rsfplegacylayouts/rsfplegacylayouts.xml"],
        "routes": [],
        "markers": r"rsfplegacylayouts|RSForm.*Legacy\s+Layouts",
    },
    "rsfp_pdf": {
        "manifests": ["/plugins/system/rsfppdf/rsfppdf.xml"],
        "routes": [],
        "markers": r"rsfppdf|RSForm.*PDF",
    },
    "rsfp_registration": {
        "manifests": ["/plugins/system/rsfpregistration/rsfpregistration.xml"],
        "routes": [],
        "markers": r"rsfpregistration|RSForm.*Registration",
    },
    "smartslider3": {
        "manifests": [
            "/plugins/system/smartslider3/smartslider3.xml",
            "/administrator/components/com_smartslider3/smartslider3.xml",
        ],
        "routes": ["/?option=com_smartslider3"],
        "markers": r"com_smartslider3|plg_system_smartslider3|Smart\s*Slider\s*3",
    },
    "sppagebuilder_pro_updater": {
        "manifests": ["/plugins/system/sppagebuilderproupdater/sppagebuilderproupdater.xml"],
        "routes": [],
        "markers": r"sppagebuilderproupdater|SP\s+Page\s+Builder.*Pro.*Updater",
    },
    "tassos_geoip": {
        "manifests": ["/plugins/system/tgeoip/tgeoip.xml"],
        "routes": [],
        "markers": r"tgeoip|Tassos.*GeoIP",
    },
}


def detect_common_component(
    target: str,
    component: str,
    timeout: int,
    proxy: str | None = None,
    baseline: dict | None = None,
) -> PluginInfo:
    """Detect a common Joomla component using public manifests and front-end routes."""
    definition = COMMON_COMPONENTS[component]
    marker = definition["markers"]
    for path in definition["manifests"]:
        response = fetch_url(f"{target.rstrip('/')}{path}", timeout=timeout, proxy=proxy)
        if is_baseline_match(response, baseline) or response.get("status") != 200:
            continue
        body = response.get("body", "")
        content_type = str(response.get("content_type", "")).lower()
        is_manifest = bool(
            "text/html" not in content_type
            and re.search(r"<(?:extension|install)\b", body, re.IGNORECASE)
            and re.search(r"<version>\s*[^<\s]+\s*</version>", body, re.IGNORECASE)
        )
        if is_manifest and re.search(marker, body, re.IGNORECASE):
            match = re.search(r"<version>\s*([^<\s]+)\s*</version>", body, re.IGNORECASE)
            edition = (
                "enterprise"
                if component == "acymailing" and re.search(r"enterprise", body, re.IGNORECASE)
                else None
            )
            return PluginInfo(True, match.group(1).strip() if match else None, path, edition)

    for path in definition["routes"]:
        response = fetch_url(f"{target.rstrip('/')}{path}", timeout=timeout, proxy=proxy)
        if is_baseline_match(response, baseline) or response.get("status") != 200:
            continue
        body = _without_request_reflections(response.get("body", ""), target, path)
        if re.search(marker, body, re.IGNORECASE):
            version_match = re.search(
                rf"(?:{marker})[^0-9]{{0,40}}([0-9]+(?:\.[0-9]+)+)", body, re.IGNORECASE
            )
            edition = (
                "enterprise"
                if component == "acymailing" and re.search(r"enterprise", body, re.IGNORECASE)
                else None
            )
            return PluginInfo(True, version_match.group(1) if version_match else None, path, edition)

    return PluginInfo(False, None, "not-detected")


def detect_plugins(
    target: str,
    args,
    baseline: dict | None = None,
    required_plugins: set[str] | list[str] | None = None,
    session: Any = None,
    concurrency: int | None = None,
) -> dict:
    from concurrent.futures import ThreadPoolExecutor

    timeout = getattr(args, "timeout", 10)
    proxy = getattr(args, "proxy", None)
    max_workers = concurrency if concurrency is not None else getattr(args, "concurrency", 5)

    all_detectors = {
        "icagenda": lambda: detect_icagenda(target, timeout, proxy=proxy, baseline=baseline),
        "baforms": lambda: detect_baforms(target, timeout, proxy=proxy, baseline=baseline),
        "sppagebuilder": lambda: detect_sppagebuilder(target, timeout, proxy=proxy, baseline=baseline),
        "pagebuilderck": lambda: detect_pagebuilderck(target, timeout, proxy=proxy, baseline=baseline),
        "rsfiles": lambda: detect_rsfiles(target, timeout, proxy=proxy, baseline=baseline),
        "helix3": lambda: detect_helix3(target, timeout, proxy=proxy, baseline=baseline),
        "helixultimate": lambda: detect_helixultimate(target, timeout, proxy=proxy, baseline=baseline),
    }
    for component in COMMON_COMPONENTS:
        all_detectors[component] = lambda component=component: detect_common_component(
            target, component, timeout, proxy=proxy, baseline=baseline
        )

    inventory_keys = set(COMMON_COMPONENTS)
    needed_keys = set(all_detectors) if required_plugins is None else set(required_plugins) | inventory_keys

    results: dict[str, dict] = {}
    for key in all_detectors:
        if key not in needed_keys:
            results[key] = {
                "found": False,
                "version": None,
                "source": "not-queried",
            }

    keys_to_run = [k for k in all_detectors if k in needed_keys]

    if keys_to_run:
        if max_workers > 1 and len(keys_to_run) > 1:
            with ThreadPoolExecutor(max_workers=min(max_workers, len(keys_to_run))) as executor:
                future_map = {executor.submit(all_detectors[k]): k for k in keys_to_run}
                for fut, k in future_map.items():
                    try:
                        info = fut.result()
                        results[k] = {
                            "found": info.found,
                            "version": info.version,
                            "source": info.source,
                            "edition": info.edition,
                        }
                    except Exception as exc:  # noqa: BLE001
                        results[k] = {
                            "found": False,
                            "version": None,
                            "source": f"error: {exc}",
                        }
        else:
            for k in keys_to_run:
                try:
                    info = all_detectors[k]()
                    results[k] = {
                        "found": info.found,
                        "version": info.version,
                        "source": info.source,
                        "edition": info.edition,
                    }
                except Exception as exc:  # noqa: BLE001
                    results[k] = {
                        "found": False,
                        "version": None,
                        "source": f"error: {exc}",
                    }

    return results
