"""Core infrastructure for models, HTTP, versioning, evidence, and probes."""

from .evidence import find_sql_errors, generate_php_math_payload, verify_php_execution
from .http import (
    HttpClient,
    HttpSession,
    build_multipart,
    fetch_url,
    form_encode,
    is_baseline_match,
    normalize_url,
    poll_paths,
    probe_target_baseline,
    request,
)
from .models import CMSInfo, Confidence, CVECheckResult, Finding, JoomlaInfo, PluginInfo, Status
from .probes import extract_csrf_from_html, find_anon_csrf_token, rand_str
from .versions import (
    normalize_version_string,
    parse_version_safe,
    version_gt,
    version_gte,
    version_in_specifier,
    version_lt,
    version_lte,
    version_parts,
)

__all__ = [
    "CMSInfo",
    "CVECheckResult",
    "Confidence",
    "Finding",
    "HttpClient",
    "HttpSession",
    "JoomlaInfo",
    "PluginInfo",
    "Status",
    "build_multipart",
    "extract_csrf_from_html",
    "fetch_url",
    "find_anon_csrf_token",
    "find_sql_errors",
    "form_encode",
    "generate_php_math_payload",
    "is_baseline_match",
    "normalize_url",
    "normalize_version_string",
    "parse_version_safe",
    "poll_paths",
    "probe_target_baseline",
    "rand_str",
    "request",
    "verify_php_execution",
    "version_gt",
    "version_gte",
    "version_in_specifier",
    "version_lt",
    "version_lte",
    "version_parts",
]
