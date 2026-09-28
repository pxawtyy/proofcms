"""Named vulnerability-chain registry."""

from .wp2shell import aggregate as aggregate_wp2shell

AVAILABLE_CHAINS = {
    "wp2shell": {
        "name": "wp2shell",
        "description": "WordPress pre-authentication RCE exposure chain",
        "cves": ["CVE-2026-63030", "CVE-2026-60137"],
        "aggregate": aggregate_wp2shell,
    }
}

__all__ = ["AVAILABLE_CHAINS", "aggregate_wp2shell"]
