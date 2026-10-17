from __future__ import annotations

from typing import Any

from .aspnet_common import metadata as build_metadata
from .aspnet_common import runtime_finding

CVE_ID = "CVE-2023-36899"
NAME = "ASP.NET elevation of privilege"
RULE = ".NET Framework 2.0 SP2 and later listed branches before the Microsoft security updates"
TYPE = "Privilege Escalation"


def check(target_url: str, cms_version: str | None = None, aspnet_runtime: dict[str, Any] | None = None, **kwargs: Any):
    return runtime_finding(cve=CVE_ID, name=NAME, rule=RULE, vulnerability_type=TYPE, remediation="Apply the applicable Microsoft .NET Framework security update and verify IIS application-pool isolation.", aspnet_runtime=aspnet_runtime)


def metadata() -> dict[str, Any]:
    return build_metadata(cve=CVE_ID, name=NAME, component="ASP.NET/.NET Framework", rule=RULE, vulnerability_type=TYPE, references=["https://nvd.nist.gov/vuln/detail/CVE-2023-36899", "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36899"])
