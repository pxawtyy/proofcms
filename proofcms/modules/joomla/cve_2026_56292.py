from __future__ import annotations

from typing import Any

from .acymailing_advisory import metadata_base, passive_only_check

CVE_ID = "CVE-2026-56292"
NAME = "AcyMailing unauthenticated SQL injection"
AFFECTED_RULE = "AcyMailing 1.0 through 10.11.0; fixed in 10.11.1"


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    plugins: dict | None = None,
    **kwargs: Any,
):
    return passive_only_check(
        cve=CVE_ID,
        name=NAME,
        affected_rule=AFFECTED_RULE,
        fixed_version="10.11.1",
        plugins=plugins,
        enterprise_only=False,
        remediation="Upgrade AcyMailing to 10.11.1 or newer and review access logs for suspicious frontend queries.",
        run_exploit_check=run_exploit_check,
    )


def metadata() -> dict[str, Any]:
    return metadata_base(
        cve=CVE_ID,
        name=NAME,
        affected_rule=AFFECTED_RULE,
        enterprise_only=False,
        references=[
            "https://www.cve.org/CVERecord?id=CVE-2026-56292",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-56292",
        ],
    )
