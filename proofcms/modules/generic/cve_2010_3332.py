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
_AXD = re.compile(r"""(?:ScriptResource|WebResource)\.axd\?d=([^"'&\s]+)""", re.IGNORECASE)
_VIEWSTATE = re.compile(r"""name=["']__VIEWSTATE["']""", re.IGNORECASE)
_SCRIPTMANAGER = re.compile(r"\bScriptManager\b", re.IGNORECASE)
_SURFACE_PATHS = ("/", "/login.aspx", "/default.aspx", "/app.aspx", "/applogin.aspx")


def _find_surface(client: HttpClient, timeout: int) -> dict[str, Any] | None:
    for path in _SURFACE_PATHS:
        page = client.get(path, timeout=timeout)
        body = str(page.get("body") or "")
        match = _AXD.search(body)
        if match:
            return {
                "path": path,
                "url": str(page.get("final_url") or path),
                "match": match,
                "viewstate": bool(_VIEWSTATE.search(body)),
                "scriptmanager": bool(_SCRIPTMANAGER.search(body)),
            }
        if _VIEWSTATE.search(body) or _SCRIPTMANAGER.search(body):
            return {
                "path": path,
                "url": str(page.get("final_url") or path),
                "match": None,
                "viewstate": bool(_VIEWSTATE.search(body)),
                "scriptmanager": bool(_SCRIPTMANAGER.search(body)),
            }
    return None


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
    runtime = aspnet_runtime or {}
    finding = legacy_passive(
        cve=CVE_ID,
        name=NAME,
        rule=RULE,
        aspnet_runtime=runtime,
        detail=(
            "If MS10-070 is not installed, the padding oracle can decrypt and forge ViewState "
            "and authentication payloads."
        ),
        remediation="Install MS10-070 or upgrade off .NET Framework 2.0; enable ViewState MAC and rotate machineKey.",
        vulnerability_type=TYPE,
        cvss=CVSS,
    )
    if finding.status != Status.LIKELY_VULNERABLE:
        return finding

    client = HttpClient(base_url=normalize_url(target_url), timeout=timeout, proxy=proxy)
    surface = _find_surface(client, timeout)
    if surface is None:
        finding.status = Status.INCONCLUSIVE
        finding.confidence = Confidence.HIGH
        finding.detail += (
            f" The 2.0.50727 header was observed at {runtime.get('source', 'an ASP.NET response')}, "
            f"but none of {', '.join(_SURFACE_PATHS)} exposed ScriptResource/WebResource, "
            "__VIEWSTATE, or ScriptManager. The MS10-070 oracle surface is absent, so the "
            "version match alone does not make this endpoint exploitable."
        )
        return finding

    finding.status = Status.LIKELY_VULNERABLE
    finding.confidence = Confidence.HIGH
    finding.evidence = {
        "surface_path": surface["path"],
        "surface_url": surface["url"],
        "viewstate": surface["viewstate"],
        "scriptmanager": surface["scriptmanager"],
    }
    if not run_exploit_check:
        return finding
    if exploit_mode != "safe":
        finding.detail += " This module supports only the safe padding-oracle differential."
        return finding
    if surface["match"] is None:
        finding.exploit_ran = True
        finding.detail += (
            " A Web Forms surface was found, but it exposed no ScriptResource/WebResource token; "
            "the oracle differential was not exercised."
        )
        return finding

    token = surface["match"].group(1)
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    resource_url = urllib.parse.urljoin(surface["url"], surface["match"].group(0))
    prefix = resource_url.split("d=", 1)[0]
    control = client.get(f"{prefix}d={urllib.parse.quote(token, safe='')}", timeout=timeout)
    probe = client.get(f"{prefix}d={urllib.parse.quote(tampered, safe='')}", timeout=timeout)
    finding.exploit_ran = True
    finding.proof_url = f"{prefix}d=<token>"
    finding.evidence = {
        **finding.evidence,
        "resource": surface["match"].group(0).split("?", 1)[0],
        "control_status": control.get("status"),
        "probe_status": probe.get("status"),
        "control_hash": control.get("body_hash"),
        "probe_hash": probe.get("body_hash"),
    }
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
        "module_version": "1.1.0",
        "last_reviewed": "2026-11-13",
        "updated": "2026-11-13",
        "required_detectors": ["aspnet"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2010-3332",
            "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-070",
        ],
    }
