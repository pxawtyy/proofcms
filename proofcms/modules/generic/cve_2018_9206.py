from __future__ import annotations

import json
import re
import secrets
from typing import Any

from ...core.http import HttpClient
from ...core.models import Confidence, Finding, Status
from ...core.versions import parse_version_safe

CVE_ID = "CVE-2018-9206"
RULE = "Blueimp jQuery File Upload through 9.22.0 with the public PHP sample handler"
HANDLERS = ("/server/php/index.php", "/jQuery-File-Upload/server/php/index.php", "/jquery-file-upload/server/php/index.php")


def classify_version(version: str | None) -> str:
    value = parse_version_safe(version)
    if value is None:
        return Status.DETECTED_VERSION_UNKNOWN
    return Status.LIKELY_VULNERABLE if value <= parse_version_safe("9.22.0") else Status.PATCHED


def _json(body: str) -> dict[str, Any]:
    try:
        data = json.loads(body)
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


def discover(target: str, timeout: int, proxy: str | None) -> dict[str, Any] | None:
    client = HttpClient(base_url=target, timeout=timeout, proxy=proxy)
    for handler in HANDLERS:
        response = client.get(handler)
        data = _json(response.get("body", ""))
        if response.get("status") == 200 and isinstance(data.get("files"), list):
            version = None
            root = handler.split("/server/php/", 1)[0]
            package = client.get(f"{root}/package.json")
            match = re.search(r'"version"\s*:\s*"([0-9.]+)"', package.get("body", ""))
            if match:
                version = match.group(1)
            return {"client": client, "handler": handler, "version": version}
    return None


def check(target_url: str, cms_version: str | None = None, run_exploit_check: bool = False,
          timeout: int = 12, proxy: str | None = None, **kwargs: Any) -> Finding:
    found = discover(target_url, timeout, proxy)
    if not found:
        return Finding(CVE_ID, "Blueimp sample handler unrestricted upload", Status.NOT_DETECTED, Confidence.MEDIUM,
                       "Web library Blueimp jQuery File Upload", affected_rule=RULE, exploit_available=True,
                       detail="The public PHP sample handler was not detected at standard paths.",
                       action="Verify manually if the sample handler is installed at a custom path.")
    status = classify_version(found.get("version"))
    proof_url = f"{target_url.rstrip('/')}{found['handler']}"
    result = Finding(CVE_ID, "Blueimp sample handler unrestricted upload", status,
                     Confidence.HIGH if found.get("version") else Confidence.MEDIUM,
                     "Web library Blueimp jQuery File Upload", found.get("version"), RULE, True,
                     detail="The anonymous Blueimp PHP sample handler is publicly reachable.",
                     action="Upgrade to 9.22.1 or newer, restrict the handler, and permit only required file types.",
                     proof_url=proof_url)
    if not run_exploit_check or status == Status.PATCHED:
        return result
    marker = f"PROOFCMS_SAFE_{secrets.token_hex(8)}"
    filename = f"proofcms_{secrets.token_hex(5)}.txt"
    response = found["client"].post(found["handler"], files={"files[]": (filename, marker.encode(), "text/plain")})
    files = _json(response.get("body", "")).get("files") or []
    uploaded = next((item for item in files if isinstance(item, dict) and item.get("name") == filename and not item.get("error")), None)
    confirmed = False
    if uploaded and uploaded.get("url"):
        confirmed = marker in found["client"].get(uploaded["url"]).get("body", "")
    if uploaded and uploaded.get("deleteUrl"):
        method = str(uploaded.get("deleteType") or "DELETE").upper()
        found["client"].request(uploaded["deleteUrl"], method=method)
    result.exploit_ran = True
    if confirmed:
        result.status, result.confidence = Status.VULNERABLE_UPLOAD_ONLY, Confidence.CONFIRMED
        result.detail = "The anonymous sample handler accepted and served a unique inert text file. This confirms unrestricted upload exposure, not PHP execution. Cleanup was requested through the handler."
    else:
        result.status, result.confidence = Status.NOT_CONFIRMED, Confidence.MEDIUM
        result.detail = "The sample handler was reachable, but an anonymous inert text upload was not accepted and read back."
    return result


def metadata() -> dict[str, Any]:
    return {"cve": CVE_ID, "cms": "generic", "name": "Blueimp sample handler unrestricted upload",
            "component": "Web library Blueimp jQuery File Upload", "affected_rule": RULE,
            "affected_versions": ["<=9.22.0"], "exploit_available": True, "exploit_modes": ["safe"],
            "intrusive": False, "references": ["https://github.com/blueimp/jQuery-File-Upload/commit/aeb47e51c67df8a504b7726595576c1c66b5dc2f", "https://nvd.nist.gov/vuln/detail/CVE-2018-9206"]}
