"""Named vulnerability-chain registry."""

from .joomla_account_takeover import aggregate as aggregate_joomla_account_takeover
from .joomla_session_to_upload import aggregate as aggregate_joomla_session_to_upload
from .joomla_token_to_upload import aggregate as aggregate_joomla_token_to_upload
from .phpinfo_origin_bypass import aggregate as aggregate_phpinfo_origin_bypass
from .wp2shell import aggregate as aggregate_wp2shell

AVAILABLE_CHAINS = {
    "joomla-account-takeover": {
        "name": "joomla-account-takeover",
        "description": "Joomla disabled-registration account creation and privilege-escalation exposure chain",
        "cves": ["CVE-2016-8870", "CVE-2016-8869"],
        "aggregate": aggregate_joomla_account_takeover,
    },
    "joomla-session-to-upload": {
        "name": "joomla-session-to-upload",
        "description": (
            "Joomla session acquisition (guest account, stale MFA state, or remember-me MFA bypass) "
            "combined with the authenticated DJ-Classifieds avatar upload"
        ),
        "cves": ["CVE-2026-90907", "CVE-2026-48897", "CVE-2026-92227", "CVE-2026-105603"],
        "aggregate": aggregate_joomla_session_to_upload,
    },
    "joomla-token-to-upload": {
        "name": "joomla-token-to-upload",
        "description": (
            "Joomla token-handling weakness in the Tassos Framework combined with the token-gated "
            "Custom Tables upload"
        ),
        "cves": ["CVE-2026-21627", "CVE-2026-105606"],
        "aggregate": aggregate_joomla_token_to_upload,
    },
    "phpinfo-to-origin-bypass": {
        "name": "phpinfo-to-origin-bypass",
        "description": (
            "phpinfo disclosure and direct origin access combined with a PHP-FPM/CGI RCE primitive"
        ),
        "cves": ["CVE-2019-11043", "CVE-2024-4577"],
        "aggregate": aggregate_phpinfo_origin_bypass,
    },
    "wp2shell": {
        "name": "wp2shell",
        "description": "WordPress pre-authentication RCE exposure chain",
        "cves": ["CVE-2026-63030", "CVE-2026-60137"],
        "aggregate": aggregate_wp2shell,
    },
}

__all__ = [
    "AVAILABLE_CHAINS",
    "aggregate_joomla_account_takeover",
    "aggregate_joomla_session_to_upload",
    "aggregate_joomla_token_to_upload",
    "aggregate_phpinfo_origin_bypass",
    "aggregate_wp2shell",
]
