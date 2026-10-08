from __future__ import annotations

from typing import Any


class VulnerabilityType:
    SQL_INJECTION = "SQL Injection"
    OBJECT_INJECTION = "Object Injection"
    ARGUMENT_INJECTION = "Argument Injection"
    FILE_UPLOAD = "Unrestricted File Upload"
    FILE_DELETION = "Arbitrary File Deletion"
    PATH_TRAVERSAL = "Path Traversal"
    SSRF = "Server-Side Request Forgery (SSRF)"
    XSS = "Cross-Site Scripting (XSS)"
    AUTHENTICATION_BYPASS = "Authentication Bypass"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    ACCESS_CONTROL = "Improper Access Control"
    OPEN_REDIRECT = "Open Redirect"
    MEMORY_CORRUPTION = "Memory Corruption"
    CODE_EXECUTION = "Remote Code Execution"
    EXPOSURE = "Exposed Attack Surface"
    OTHER = "Other"


_CVE_TYPES = {
    "CVE-2015-8562": VulnerabilityType.OBJECT_INJECTION,
    "CVE-2016-8869": VulnerabilityType.PRIVILEGE_ESCALATION,
    "CVE-2016-8870": VulnerabilityType.ACCESS_CONTROL,
    "CVE-2019-19576": VulnerabilityType.FILE_UPLOAD,
    "CVE-2019-19634": VulnerabilityType.FILE_UPLOAD,
    "CVE-2026-21627": VulnerabilityType.ACCESS_CONTROL,
    "CVE-2026-49049": VulnerabilityType.ACCESS_CONTROL,
    "CVE-2026-48908": VulnerabilityType.FILE_UPLOAD,
    "CVE-2026-57830": VulnerabilityType.FILE_DELETION,
    "CVE-2026-78079": VulnerabilityType.OPEN_REDIRECT,
    "CVE-2026-90915": VulnerabilityType.FILE_DELETION,
    "CVE-2026-92222": VulnerabilityType.SSRF,
    "CVE-2023-28121": VulnerabilityType.AUTHENTICATION_BYPASS,
    "CVE-2023-32243": VulnerabilityType.PRIVILEGE_ESCALATION,
    "CVE-2023-3460": VulnerabilityType.PRIVILEGE_ESCALATION,
    "CVE-2024-10924": VulnerabilityType.AUTHENTICATION_BYPASS,
    "CVE-2024-28000": VulnerabilityType.PRIVILEGE_ESCALATION,
    "CVE-2026-63030": VulnerabilityType.ACCESS_CONTROL,
    "CVE-2026-73373": VulnerabilityType.FILE_UPLOAD,
    "CVE-2026-87902": VulnerabilityType.PATH_TRAVERSAL,
    "CVE-2012-1823": VulnerabilityType.ARGUMENT_INJECTION,
    "CVE-2019-11043": VulnerabilityType.MEMORY_CORRUPTION,
    "CVE-2024-4577": VulnerabilityType.ARGUMENT_INJECTION,
    "CVE-2021-23394": VulnerabilityType.FILE_UPLOAD,
    "CVE-2026-81891": VulnerabilityType.FILE_UPLOAD,
    "PROOFCMS-K2-REGISTRATION-AVATAR": VulnerabilityType.EXPOSURE,
}


def classify_vulnerability_type(cve: str, name: str = "") -> str:
    """Return a stable, human-readable category for a registered check."""
    if cve in _CVE_TYPES:
        return _CVE_TYPES[cve]
    lowered = name.lower()
    keyword_types = (
        (("sql injection", "sqli"), VulnerabilityType.SQL_INJECTION),
        (("cross-site scripting", " xss"), VulnerabilityType.XSS),
        (("server-side request forgery", "ssrf"), VulnerabilityType.SSRF),
        (("open redirect",), VulnerabilityType.OPEN_REDIRECT),
        (("privilege escalation",), VulnerabilityType.PRIVILEGE_ESCALATION),
        (("authentication bypass",), VulnerabilityType.AUTHENTICATION_BYPASS),
        (("path traversal", "directory traversal"), VulnerabilityType.PATH_TRAVERSAL),
        (("file deletion", "directory deletion"), VulnerabilityType.FILE_DELETION),
        (("file upload", "upload bypass", "unrestricted upload"), VulnerabilityType.FILE_UPLOAD),
        (("object injection", "deserialization"), VulnerabilityType.OBJECT_INJECTION),
        (("argument injection", "option injection"), VulnerabilityType.ARGUMENT_INJECTION),
        (("remote code execution", " rce"), VulnerabilityType.CODE_EXECUTION),
        (("access control", "route confusion"), VulnerabilityType.ACCESS_CONTROL),
    )
    for keywords, category in keyword_types:
        if any(keyword in lowered for keyword in keywords):
            return category
    return VulnerabilityType.OTHER


def normalize_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    """Copy module metadata and ensure it exposes the normalized category."""
    normalized = dict(metadata)
    normalized["vulnerability_type"] = normalized.get("vulnerability_type") or classify_vulnerability_type(
        str(normalized.get("cve") or ""), str(normalized.get("name") or "")
    )
    return normalized
