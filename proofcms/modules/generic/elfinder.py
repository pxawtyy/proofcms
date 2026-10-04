from __future__ import annotations

import io
import json
import re
import zipfile
from typing import Any
from urllib.parse import urlencode, urlsplit

from ...core.http import HttpClient

CONNECTORS = (
    "/elfinder/php/connector.minimal.php",
    "/elfinder/php/connector.php",
    "/assets/elfinder/php/connector.minimal.php",
    "/assets/elfinder/php/connector.php",
    "/vendor/studio-42/elfinder/php/connector.minimal.php",
)
_DISCOVERY_CACHE: dict[tuple[str, int, str | None], dict[str, Any] | None] = {}


def _json(response: dict[str, Any]) -> dict[str, Any]:
    try:
        value = json.loads(response.get("body", ""))
        return value if isinstance(value, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def discover(target: str, timeout: int, proxy: str | None) -> dict[str, Any] | None:
    cache_key = (target.rstrip("/"), timeout, proxy)
    if cache_key in _DISCOVERY_CACHE:
        return _DISCOVERY_CACHE[cache_key]
    client = HttpClient(base_url=target, timeout=timeout, proxy=proxy)
    for path in CONNECTORS:
        response = client.get(f"{path}?cmd=open&target=l1_Lw&init=1")
        data = _json(response)
        cwd = data.get("cwd") or {}
        if response.get("status") == 200 and isinstance(cwd, dict) and cwd.get("hash") and data.get("api"):
            version = None
            root = path.split("/php/", 1)[0]
            changelog = client.get(f"{root}/Changelog")
            match = re.search(r"elFinder\s*\((2\.1\.\d+)\)", changelog.get("body", ""), re.IGNORECASE)
            if match:
                version = match.group(1)
            result = {
                "client": client,
                "endpoint": path,
                "target": cwd["hash"],
                "version": version,
                "api": data.get("api"),
                "csrf": data.get("csrf"),
            }
            _DISCOVERY_CACHE[cache_key] = result
            return result
    _DISCOVERY_CACHE[cache_key] = None
    return None


def command(conn: dict[str, Any], fields: dict[str, Any]) -> dict[str, Any]:
    headers = {"X-elFinder-CSRF": conn["csrf"]} if conn.get("csrf") else None
    response = conn["client"].post(conn["endpoint"], fields=fields, headers=headers)
    return _json(response)


def upload(conn: dict[str, Any], filename: str, content: bytes, content_type: str) -> dict[str, Any]:
    headers = {"X-elFinder-CSRF": conn["csrf"]} if conn.get("csrf") else None
    response = conn["client"].post(
        conn["endpoint"],
        fields={"cmd": "upload", "target": conn["target"]},
        files={"upload[]": (filename, content, content_type)},
        headers=headers,
    )
    return _json(response)


def first_added(data: dict[str, Any], name: str | None = None) -> dict[str, Any] | None:
    added = data.get("added") or []
    for item in added:
        if isinstance(item, dict) and item.get("hash") and (name is None or item.get("name") == name):
            return item
    return None


def read_file(conn: dict[str, Any], file_hash: str) -> str:
    query = urlencode({"cmd": "file", "target": file_hash, "download": "1"})
    return str(conn["client"].get(f"{conn['endpoint']}?{query}").get("body", ""))


def cleanup(conn: dict[str, Any], hashes: list[str]) -> None:
    for file_hash in dict.fromkeys(filter(None, hashes)):
        command(conn, {"cmd": "rm", "targets[]": file_hash})


def zip_payload(filename: str, content: bytes) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(filename, content)
    return stream.getvalue()


def endpoint_url(target: str, conn: dict[str, Any]) -> str:
    parsed = urlsplit(target)
    return f"{parsed.scheme}://{parsed.netloc}{conn['endpoint']}"
