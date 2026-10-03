"""Named vulnerability-chain registry."""

from .joomla_account_takeover import aggregate as aggregate_joomla_account_takeover
from .wp2shell import aggregate as aggregate_wp2shell

AVAILABLE_CHAINS = {
    "joomla-account-takeover": {
        "name": "joomla-account-takeover",
        "description": "Joomla disabled-registration account creation and privilege-escalation exposure chain",
        "cves": ["CVE-2016-8870", "CVE-2016-8869"],
        "aggregate": aggregate_joomla_account_takeover,
    },
    "wp2shell": {
        "name": "wp2shell",
        "description": "WordPress pre-authentication RCE exposure chain",
        "cves": ["CVE-2026-63030", "CVE-2026-60137"],
        "aggregate": aggregate_wp2shell,
    },
}

__all__ = ["AVAILABLE_CHAINS", "aggregate_joomla_account_takeover", "aggregate_wp2shell"]
