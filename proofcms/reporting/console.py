from __future__ import annotations

import importlib
import re
import urllib.parse
from copy import deepcopy
from typing import Any

from ..core.categories import normalize_metadata
from ..core.models import CMSInfo

SENSITIVE_QUERY_KEYS = {
    "access_token", "api_key", "apikey", "auth", "authorization", "key", "nonce",
    "password", "passwd", "secret", "sig", "signature", "token",
}


def redact_url(value: str) -> str:
    """Redact URL credentials and commonly sensitive query parameters."""
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return value
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return value
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    netloc = ("***@" if parsed.username is not None else "") + host + (f":{port}" if port else "")
    query = urllib.parse.urlencode(
        [(key, "***" if key.lower() in SENSITIVE_QUERY_KEYS else item) for key, item in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)],
        doseq=True,
    )
    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, query, parsed.fragment))


def redact_text(value: str) -> str:
    """Redact every HTTP(S) URL embedded in free-form text."""
    return re.sub(r"https?://[^\s'\"<>]+", lambda match: redact_url(match.group(0)), value)


def redact_output(value: Any) -> Any:
    """Return a report-safe copy with URLs and sensitive mapping keys redacted."""
    if isinstance(value, dict):
        return {
            key: "***" if str(key).lower() in SENSITIVE_QUERY_KEYS else redact_output(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_output(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_output(item) for item in value)
    if isinstance(value, str):
        return redact_text(value)
    return deepcopy(value)


def strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*[mK]", "", text)


def sanitize_argv(argv: list[str]) -> list[str]:
    """Sanitizes sensitive arguments from command line before recording in reports."""
    sanitized: list[str] = []
    skip_next = False
    for i, arg in enumerate(argv):
        if skip_next:
            skip_next = False
            continue
        if arg == "--proxy":
            sanitized.append("--proxy")
            sanitized.append("***")
            skip_next = True
        elif arg.startswith("--proxy="):
            sanitized.append("--proxy=***")
        elif arg == "--aggressive-command":
            sanitized.append("--aggressive-command")
            sanitized.append("[COMMAND_PROVIDED]")
            skip_next = True
        elif arg.startswith("--aggressive-command="):
            sanitized.append("--aggressive-command=[COMMAND_PROVIDED]")
        elif arg in ("--reverse-host", "--reverse-port", "--token", "--api-key", "--password"):
            sanitized.append(arg)
            sanitized.append("***")
            skip_next = True
        elif any(
            arg.startswith(f"{prefix}=")
            for prefix in ("--reverse-host", "--reverse-port", "--token", "--api-key", "--password")
        ):
            prefix, _ = arg.split("=", 1)
            sanitized.append(f"{prefix}=***")
        elif arg in {"-u", "--url"} and i + 1 < len(argv):
            sanitized.extend([arg, redact_url(argv[i + 1])])
            skip_next = True
        elif arg.startswith("--url="):
            sanitized.append("--url=" + redact_url(arg.split("=", 1)[1]))
        else:
            sanitized.append(redact_url(arg))
    return sanitized


def print_banner(tool_name: str = "ProofCMS"):
    print(f"{tool_name} - CMS vulnerability validation hub")
    print("=" * 58)
    print("Responsible use: run only against applications you own or are explicitly")
    print("authorized to audit. This tool is intended for defensive security testing.")
    print("SAFE verification: controlled proofs for authorized audits only.")
    print("AGGRESSIVE verification: blind RCE/raw PoCs for isolated labs only.")
    print("All active verification is disabled by default.")
    print("=" * 58)
    print()


def status_color(status: str) -> str:
    return {
        "VULNERABLE": "\033[91m",
        "VULNERABLE_UPLOAD_ONLY": "\033[93m",
        "LIKELY_VULNERABLE": "\033[91m",
        "INCONCLUSIVE": "\033[93m",
        "DETECTED_VERSION_UNKNOWN": "\033[33m",
        "PATCHED": "\033[92m",
        "NOT_AFFECTED": "\033[94m",
        "NOT_DETECTED": "\033[36m",
        "NOT_CONFIRMED": "\033[93m",
        "BLOCKED_EXTERNAL": "\033[33m",
        "AGGRESSIVE_READY": "\033[95m",
        "AGGRESSIVE_SENT": "\033[95m",
        "NOT_JOOMLA": "\033[90m",
        "ERROR": "\033[91m",
    }.get(status, "\033[97m")


def is_joomla_core_result(result: dict | Any) -> bool:
    comp = result.get("component", "") if isinstance(result, dict) else getattr(result, "component", "")
    return str(comp).lower().startswith("joomla core")


def is_wordpress_core_result(result: dict | Any) -> bool:
    comp = result.get("component", "") if isinstance(result, dict) else getattr(result, "component", "")
    return str(comp).lower().startswith("wordpress core")


def is_php_runtime_result(result: dict | Any) -> bool:
    comp = result.get("component", "") if isinstance(result, dict) else getattr(result, "component", "")
    return str(comp).lower().startswith("php runtime")


def is_generic_web_result(result: dict | Any) -> bool:
    comp = result.get("component", "") if isinstance(result, dict) else getattr(result, "component", "")
    return str(comp).lower().startswith(("web library", "nginx runtime"))


def visible_results(
    results: list[dict | Any],
    show_patched: bool = False,
    show_not_detected: bool = False,
    show_all: bool = False,
) -> tuple[list[dict | Any], dict[str, int]]:
    hidden = {"PATCHED": 0, "NOT_DETECTED": 0, "NOT_AFFECTED": 0}
    visible = []
    for result in results:
        status = result.get("status") if isinstance(result, dict) else getattr(result, "status", None)
        if status == "PATCHED" and not (show_patched or show_all):
            hidden["PATCHED"] += 1
            continue
        if status == "NOT_DETECTED" and not (show_not_detected or show_all):
            hidden["NOT_DETECTED"] += 1
            continue
        if status == "NOT_AFFECTED" and not show_all:
            hidden["NOT_AFFECTED"] += 1
            continue
        visible.append(result)
    return visible, hidden


def hidden_results_note(hidden: dict[str, int]) -> str | None:
    labels = []
    if hidden.get("PATCHED"):
        labels.append(f"{hidden['PATCHED']} PATCHED")
    if hidden.get("NOT_DETECTED"):
        labels.append(f"{hidden['NOT_DETECTED']} NOT_DETECTED")
    if hidden.get("NOT_AFFECTED"):
        labels.append(f"{hidden['NOT_AFFECTED']} NOT_AFFECTED")
    if not labels:
        return None
    return f"{', '.join(labels)} result(s) hidden. Use --show-all to display everything."


def print_cve_catalog(available_cves: dict[str, str], available_chains: dict[str, dict] | None = None):
    print("Available CVEs:")
    for cve_id, module_name in available_cves.items():
        module = importlib.import_module(module_name)
        meta = normalize_metadata(module.metadata())
        modes = ",".join(meta.get("exploit_modes", [])) or "none"
        exploit = "yes" if meta.get("exploit_available") else "no"
        proof_kind = (
            "passive"
            if not meta.get("exploit_available")
            else "intrusive"
            if meta.get("intrusive")
            else "active-safe"
            if modes != "none"
            else "passive"
        )
        cms_key = str(meta.get("cms", "joomla")).lower()
        cms = {"joomla": "Joomla", "wordpress": "WordPress"}.get(cms_key, cms_key.title())
        versions = ",".join(meta.get("affected_joomla_versions", meta.get("affected_versions", ["unknown"])))
        print(
            f"- {cve_id}: {meta.get('name')} | type: {meta.get('vulnerability_type')} | {cms}: {versions} | "
            f"rule: {meta.get('affected_rule')} | exploit: {exploit} ({proof_kind}; modes: {modes})"
        )
    if available_chains:
        print("\nAvailable attack chains:")
        for chain_id, chain in available_chains.items():
            print(f"- {chain_id}: {chain.get('description')} | components: {','.join(chain.get('cves', []))}")


def print_chain_results(chains: list[dict[str, Any]]):
    if not chains:
        return
    print("[Attack chains]")
    for chain in chains:
        color = status_color(chain["status"])
        reset = "\033[0m"
        print(f"{color}{chain['chain']}: {chain['status']} ({chain['confidence']}){reset}")
        print(f"  Components: {', '.join(chain.get('components', []))}")
        print(f"  Detail: {chain['detail']}")
        print(f"  Action: {chain['action']}")
    print()


def print_one_result(result: dict | Any):
    res_dict = result if isinstance(result, dict) else result.as_dict()
    color = status_color(res_dict["status"])
    reset = "\033[0m"
    print(f"{color}{res_dict['cve']}: {res_dict['status']} ({res_dict['confidence']}){reset}")
    print(f"  Vulnerability type: {res_dict.get('vulnerability_type') or 'Other'}")
    print(f"  Component: {res_dict['component']} {res_dict['component_version'] or 'unknown'}")
    print(f"  Rule: {res_dict['affected_rule']}")
    print(f"  Detail: {res_dict['detail']}")
    print(f"  Action: {res_dict['action']}")
    if res_dict.get("exploit_available"):
        if res_dict.get("exploit_ran"):
            state = "ran"
        elif res_dict.get("exploit_requested"):
            state = f"requested but skipped for mode '{res_dict.get('requested_exploit_mode')}'"
        else:
            state = "available, not run"
        print(f"  Exploit: {state}")
    if res_dict.get("proof_url"):
        print(f"  Proof URL: {redact_url(res_dict['proof_url'])}")
    if res_dict.get("uploaded_filename"):
        if res_dict["status"] in {"VULNERABLE", "VULNERABLE_UPLOAD_ONLY"}:
            print(f"  Cleanup: delete uploaded file {res_dict['uploaded_filename']}")
        else:
            print(f"  Cleanup: if present, delete uploaded file {res_dict['uploaded_filename']}")
    if res_dict.get("cleanup_attempted"):
        print(f"  Cleanup verified: {'yes' if res_dict.get('cleanup_verified') else 'no'}")
    if res_dict.get("evidence"):
        print(f"  Evidence: {redact_output(res_dict['evidence'])}")


def print_result(
    target: str,
    info: CMSInfo,
    results: list[dict | Any],
    show_patched: bool = False,
    show_not_detected: bool = False,
    show_all: bool = False,
    php_runtime: dict[str, Any] | None = None,
    nginx_runtime: dict[str, Any] | None = None,
    errors: list[str] | None = None,
):
    reset = "\033[0m"
    print(f"Target: {redact_url(target)}")
    cms_name = info.name if info.detected else "unknown"
    print(
        f"CMS: {cms_name} | detected: {'yes' if info.detected else 'no'} | "
        f"version: {info.version or 'unknown'} | source: {info.source}"
    )
    for error in errors or []:
        print(f"{status_color('ERROR')}Error: {redact_text(error)}{reset}")
    runtime = php_runtime or {}
    print(
        f"PHP: detected: {'yes' if runtime.get('detected') else 'no'} | "
        f"version: {runtime.get('version') or 'unknown'} | source: {runtime.get('source') or 'not-detected'}"
    )
    nginx = nginx_runtime or {}
    print(
        f"NGINX: detected: {'yes' if nginx.get('detected') else 'no'} | "
        f"version: {nginx.get('version') or 'unknown'} | source: {nginx.get('source') or 'not-detected'} | "
        f"HTTP/3 advertised: {'yes' if nginx.get('http3_advertised') else 'no'}"
    )
    if not info.detected:
        print(f"{status_color('NOT_JOOMLA')}Status: UNKNOWN_CMS{reset}")
    filtered, hidden = visible_results(results, show_patched, show_not_detected, show_all)
    php_results = [result for result in filtered if is_php_runtime_result(result)]
    generic_results = [result for result in filtered if is_generic_web_result(result)]
    cms_results = [result for result in filtered if not is_php_runtime_result(result) and not is_generic_web_result(result)]
    if info.name == "wordpress":
        sections = [
            ("PHP runtime", php_results),
            ("Generic web components", generic_results),
            ("WordPress core", [result for result in cms_results if is_wordpress_core_result(result)]),
            ("WordPress plugins", [result for result in cms_results if not is_wordpress_core_result(result)]),
        ]
    else:
        sections = [
            ("PHP runtime", php_results),
            ("Generic web components", generic_results),
            ("Joomla core/framework", [result for result in cms_results if is_joomla_core_result(result)]),
            ("Plugins/components", [result for result in cms_results if not is_joomla_core_result(result)]),
        ]
    for title, section_results in sections:
        if not section_results:
            continue
        print(f"\n[{title}]")
        for result in section_results:
            print_one_result(result)
    note = hidden_results_note(hidden)
    if note:
        print(f"\n({note})")
    print()


def print_plugins(
    plugins: dict,
    title: str = "Plugins/components",
    show_not_detected: bool = False,
    show_all: bool = False,
):
    if not plugins:
        return
    visible = {
        name: data
        for name, data in plugins.items()
        if data.get("found") or data.get("state") == "error" or show_not_detected or show_all
    }
    if not visible:
        print(f"{title}: none detected from public manifests/routes")
        return
    print(f"{title}:")
    for name, data in visible.items():
        found = "yes" if data.get("found") else "no"
        version = data.get("version") or "unknown"
        source = data.get("source") or "unknown"
        edition = f" | edition: {data.get('edition')}" if data.get("edition") else ""
        print(f"  {name}: {found} | version: {version} | source: {source}{edition}")


def print_wordpress_inventory(inventory: dict):
    theme = inventory.get("theme") or {}
    if theme.get("found"):
        print("WordPress theme:")
        print(
            f"  {theme.get('name')}: yes | version: {theme.get('version') or 'unknown'} | "
            f"source: {theme.get('source') or 'unknown'}"
        )
    plugins = inventory.get("plugins") or {}
    if plugins:
        print_plugins(plugins, title="WordPress plugins")
    else:
        print("WordPress plugins: none detected from public assets/probes")
