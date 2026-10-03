from __future__ import annotations

from typing import Any

from .acymailing_advisory import metadata_base, passive_only_check

CVE_ID = "CVE-2026-94132"
NAME = "AcyMailing Enterprise mailbox attachment RCE"
AFFECTED_RULE = "AcyMailing Enterprise 1.0.0 through 11.0.5; fixed in 11.1.0"


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
        fixed_version="11.1.0",
        plugins=plugins,
        enterprise_only=True,
        remediation=(
            "Upgrade AcyMailing Enterprise to 11.1.0 or newer and inspect media/com_acym/upload/ for executable files."
        ),
        run_exploit_check=run_exploit_check,
    )


def metadata() -> dict[str, Any]:
    return metadata_base(
        cve=CVE_ID,
        name=NAME,
        affected_rule=AFFECTED_RULE,
        enterprise_only=True,
        references=["https://www.cve.org/CVERecord?id=CVE-2026-94132"],
    )
