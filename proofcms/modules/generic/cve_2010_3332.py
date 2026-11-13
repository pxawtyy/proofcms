from __future__ import annotations

import re
import urllib.parse
from typing import Any

from ...core.http import HttpClient, normalize_url
from ...core.models import Confidence, Status
from .aspnet_legacy_common import legacy_passive

CVE_ID = "CVE-2010-3332"
NAME = "ASP.NET padding oracle (MS10-070)"
RULE = "ASP.NET 1.1 SP1, 2.0 SP1/SP2, 3.5, 3.5.1, and 4.0 without MS10-070"
TYPE = "Information Disclosure / Remote Code Execution"
CVSS = "9.1"
_RE = re.compile(r"""(?:ScriptResource|WebResource)\.axd\?d=([^"'&\s]+)""", re.IGNORECASE)


def check(
    target_url: str,
    cms_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aspnet_runtime: dict[str, Any] | None = None,
    **kwargs: Any,
):
    del cms_version, kwargs
    finding = legacy_passive(
        cve=CVE_ID,
        name=NAME,
        rule=RULE,
        aspnet_runtime=aspnet_runtime,
        detail=(
            "If MS10-070 is not installed, the padding oracle can decrypt and forge ViewState "
            "and authentication payloads."
        ),
        remediation="Install MS10-070 or upgrade off .NET Framework 2.0; enable ViewState MAC and rotate machineKey.",
        vulnerability_type=TYPE,
        cvss=CVSS,
    )
    if not run_exploit_check or finding.status != Status.LIKELY_VULNERABLE:
        return finding
    if exploit_mode != "safe":
        finding.detail += " This module supports only the safe padding-oracle differential."
        return finding

    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    page = client.get("/", timeout=timeout)
    body = str(page.get("body") or "")
    match = _RE.search(body)
    if not match:
        finding.exploit_ran = True
        finding.status = Status.LIKELY_VULNERABLE
        finding.confidence = Confidence.HIGH
        finding.detail += (
            " No ScriptResource/WebResource token was exposed on the landing page, so the remote "
            "oracle differential could not be exercised; the EOL runtime remains the finding."
        )
        return finding

    token = match.group(1)
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    path = match.group(0).split("?", 1)[0]
    control = client.get(f"{base}/{path}?d={urllib.parse.quote(token, safe='')}", timeout=timeout)
    probe = client.get(f"{base}/{path}?d={urllib.parse.quote(tampered, safe='')}", timeout=timeout)
    evidence = {
        "resource": path,
        "control_status": control.get("status"),
        "probe_status": probe.get("status"),
        "control_hash": control.get("body_hash"),
        "probe_hash": probe.get("body_hash"),
    }
    finding.exploit_ran = True
    finding.proof_url = f"{base}/{path}?d=<token>"
    finding.evidence = evidence
    if (
        control.get("status") == 200
        and probe.get("status") == 500
        and control.get("body_hash") != probe.get("body_hash")
    ):
        finding.status = Status.VULNERABLE
        finding.confidence = Confidence.CONFIRMED
        finding.detail = (
            "A valid ScriptResource/WebResource token returned 200 while a single-character "
            "tamper returned 500 with a different body, the MS10-070 padding-oracle differential. "
            "No plaintext was decrypted."
        )
    else:
        finding.status = Status.NOT_CONFIRMED
        finding.confidence = Confidence.MEDIUM
        finding.detail = (
            "The token did not produce the control/tamper status differential "
            f"(control={control.get('status')}, probe={probe.get('status')})."
        )
    return finding


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "generic",
        "name": NAME,
        "component": "ASP.NET/.NET Framework",
        "affected_rule": RULE,
        "affected_versions": [".NET 1.1 SP1", ".NET 2.0 SP1/SP2", ".NET 3.5", ".NET 3.5.1", ".NET 4.0"],
        "exploit_available": True,
        "exploit_modes": ["safe"],
        "intrusive": False,
        "vulnerability_type": TYPE,
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-13",
        "updated": "2026-11-13",
        "required_detectors": ["aspnet"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2010-3332",
            "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-070",
        ],
    }
