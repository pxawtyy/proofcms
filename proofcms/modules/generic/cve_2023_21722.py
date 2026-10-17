from __future__ import annotations

from typing import Any

from .aspnet_common import metadata as build_metadata
from .aspnet_common import runtime_finding

CVE_ID = "CVE-2023-21722"
NAME = ".NET Framework denial of service"
RULE = ".NET Framework 2.0 SP2 before 2.0.50727.8966 and other Microsoft-listed branches"
TYPE = "Denial of Service"


def check(target_url: str, cms_version: str | None = None, aspnet_runtime: dict[str, Any] | None = None, **kwargs: Any):
    return runtime_finding(cve=CVE_ID, name=NAME, rule=RULE, vulnerability_type=TYPE, remediation="Apply the applicable Microsoft .NET Framework security update; do not send crash payloads to production services.", aspnet_runtime=aspnet_runtime)


def metadata() -> dict[str, Any]:
    return build_metadata(cve=CVE_ID, name=NAME, component="ASP.NET/.NET Framework", rule=RULE, vulnerability_type=TYPE, references=["https://nvd.nist.gov/vuln/detail/CVE-2023-21722", "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21722"])
