from __future__ import annotations

import re
from typing import Any

from ..core.http import fetch_url, is_baseline_match
from ..core.models import JoomlaInfo, PluginInfo


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
            and response["status"] == 200
            and re.search(r"icagenda|com_icagenda", body, re.IGNORECASE)
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
        if response["status"] == 200 and re.search(r"baforms|balbooa", body, re.IGNORECASE):
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
            if response["status"] == 403:
                return PluginInfo(True, None, f"{path} (403-public-exec-blocked)")
            if response["status"] == 200:
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
            response["status"] == 200
            and re.search(r"sppagebuilder|sp page builder|com_sppagebuilder", body, re.IGNORECASE)
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
        if response["status"] == 200 and re.search(r"pagebuilderck|Page\s*Builder\s*CK", body, re.IGNORECASE):
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
        if response["status"] == 200 and re.search(r"rsfiles|com_rsfiles", body, re.IGNORECASE):
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
        if response["status"] == 200 and re.search(r"helix3|shaper_helix3|JoomShaper", body, re.IGNORECASE):
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
        if (
            response["status"] == 200
            and re.search(r"helixultimate|shaper_helixultimate|Helix\s*Ultimate", body, re.IGNORECASE)
        ):
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

    needed_keys = set(all_detectors.keys()) if required_plugins is None else set(required_plugins)

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
                    }
                except Exception as exc:  # noqa: BLE001
                    results[k] = {
                        "found": False,
                        "version": None,
                        "source": f"error: {exc}",
                    }

    return results
