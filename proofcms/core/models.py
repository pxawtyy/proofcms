from dataclasses import dataclass

from .categories import classify_vulnerability_type


class Status:
    VULNERABLE = "VULNERABLE"
    VULNERABLE_UPLOAD_ONLY = "VULNERABLE_UPLOAD_ONLY"
    LIKELY_VULNERABLE = "LIKELY_VULNERABLE"
    INCONCLUSIVE = "INCONCLUSIVE"
    DETECTED_VERSION_UNKNOWN = "DETECTED_VERSION_UNKNOWN"
    PATCHED = "PATCHED"
    NOT_AFFECTED = "NOT_AFFECTED"
    NOT_DETECTED = "NOT_DETECTED"
    NOT_CONFIRMED = "NOT_CONFIRMED"
    BLOCKED_EXTERNAL = "BLOCKED_EXTERNAL"
    AGGRESSIVE_READY = "AGGRESSIVE_READY"
    AGGRESSIVE_SENT = "AGGRESSIVE_SENT"
    NOT_JOOMLA = "NOT_JOOMLA"
    ERROR = "ERROR"


class Confidence:
    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Finding:
    """Unified finding returned by all vulnerability checking modules."""

    cve: str
    name: str
    status: str
    confidence: str
    component: str = ""
    component_version: str | None = None
    affected_rule: str = ""
    exploit_available: bool = False
    exploit_ran: bool = False
    exploit_requested: bool = False
    detail: str = ""
    action: str = ""
    requested_exploit_mode: str | None = None
    requested_exploit_mode_input: str | None = None
    proof_url: str | None = None
    uploaded_filename: str | None = None
    evidence: dict | None = None
    cleanup_attempted: bool = False
    cleanup_verified: bool = False
    vulnerability_type: str = ""

    def __post_init__(self) -> None:
        if not self.vulnerability_type:
            self.vulnerability_type = classify_vulnerability_type(self.cve, self.name)

    def as_dict(self) -> dict:
        return {
            "cve": self.cve,
            "name": self.name,
            "vulnerability_type": self.vulnerability_type,
            "status": self.status,
            "confidence": self.confidence,
            "component": self.component,
            "component_version": self.component_version,
            "affected_rule": self.affected_rule,
            "exploit_available": self.exploit_available,
            "exploit_ran": self.exploit_ran,
            "exploit_requested": self.exploit_requested,
            "requested_exploit_mode": self.requested_exploit_mode,
            "requested_exploit_mode_input": self.requested_exploit_mode_input,
            "proof_url": self.proof_url,
            "uploaded_filename": self.uploaded_filename,
            "evidence": self.evidence,
            "cleanup_attempted": self.cleanup_attempted,
            "cleanup_verified": self.cleanup_verified,
            "detail": self.detail,
            "action": self.action,
        }

    def __getitem__(self, item: str):
        return getattr(self, item)

    def get(self, item: str, default=None):
        return getattr(self, item, default)


# Backwards compatibility alias for existing modules/tests
CVECheckResult = Finding


@dataclass
class CMSInfo:
    name: str
    detected: bool
    version: str | None
    source: str
    raw: str = ""
    base_url: str | None = None


@dataclass
class PluginInfo:
    found: bool
    version: str | None
    source: str
    edition: str | None = None


@dataclass
class JoomlaInfo:
    detected: bool
    version: str | None
    source: str
    raw: str = ""


@dataclass
class PHPRuntimeInfo:
    detected: bool
    version: str | None
    source: str
    server: str | None = None
    entrypoint: str = "/index.php"
    phpinfo_exposed: bool = False
    phpinfo_path: str | None = None
    phpinfo_size: int | None = None
    origin_ip: str | None = None
    origin_reachable: bool = False
    origin_server: str | None = None


@dataclass
class NginxRuntimeInfo:
    detected: bool
    version: str | None
    source: str
    server: str | None = None
    http3_advertised: bool = False
    edge_server: str | None = None
    edge_http3_advertised: bool = False
