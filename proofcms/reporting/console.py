from __future__ import annotations

import importlib
import re
from typing import Any

from ..core.models import CMSInfo


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
        else:
            sanitized.append(arg)
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


def visible_results(results: list[dict | Any], show_patched: bool) -> tuple[list[dict | Any], int]:
    hidden = 0
    visible = []
    for result in results:
        status = result.get("status") if isinstance(result, dict) else getattr(result, "status", None)
        if status == "PATCHED" and not show_patched:
            hidden += 1
            continue
        visible.append(result)
    return visible, hidden


def print_cve_catalog(available_cves: dict[str, str], available_chains: dict[str, dict] | None = None):
    print("Available CVEs:")
    for cve_id, module_name in available_cves.items():
        module = importlib.import_module(module_name)
        meta = module.metadata()
        modes = ",".join(meta.get("exploit_modes", [])) or "none"
        exploit = "yes" if meta.get("exploit_available") else "no"
        intrusive = "intrusive" if meta.get("intrusive") else "passive"
        cms_key = str(meta.get("cms", "joomla")).lower()
        cms = {"joomla": "Joomla", "wordpress": "WordPress"}.get(cms_key, cms_key.title())
        versions = ",".join(meta.get("affected_joomla_versions", meta.get("affected_versions", ["unknown"])))
        print(
            f"- {cve_id}: {meta.get('name')} | {cms}: {versions} | "
            f"rule: {meta.get('affected_rule')} | exploit: {exploit} ({intrusive}; modes: {modes})"
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
        print(f"  Proof URL: {res_dict['proof_url']}")
    if res_dict.get("uploaded_filename"):
        if res_dict["status"] in {"VULNERABLE", "VULNERABLE_UPLOAD_ONLY"}:
            print(f"  Cleanup: delete uploaded file {res_dict['uploaded_filename']}")
        else:
            print(f"  Cleanup: if present, delete uploaded file {res_dict['uploaded_filename']}")


def print_result(target: str, info: CMSInfo, results: list[dict | Any], show_patched: bool = False):
    reset = "\033[0m"
    print(f"Target: {target}")
    cms_name = info.name if info.detected else "unknown"
    print(
        f"CMS: {cms_name} | detected: {'yes' if info.detected else 'no'} | "
        f"version: {info.version or 'unknown'} | source: {info.source}"
    )
    if not info.detected:
        print(f"{status_color('NOT_JOOMLA')}Status: UNKNOWN_CMS{reset}")
        print()
        return
    filtered, hidden = visible_results(results, show_patched)
    if info.name == "wordpress":
        sections = [
            ("WordPress core", [result for result in filtered if is_wordpress_core_result(result)]),
            ("WordPress plugins", [result for result in filtered if not is_wordpress_core_result(result)]),
        ]
    else:
        sections = [
            ("Joomla core/framework", [result for result in filtered if is_joomla_core_result(result)]),
            ("Plugins/components", [result for result in filtered if not is_joomla_core_result(result)]),
        ]
    for title, section_results in sections:
        if not section_results:
            continue
        print(f"\n[{title}]")
        for result in section_results:
            print_one_result(result)
    if hidden:
        print(f"\n({hidden} PATCHED result(s) hidden. Use --show-patched to display.)")
    print()


def print_plugins(plugins: dict, title: str = "Plugins/components"):
    if not plugins:
        return
    print(f"{title}:")
    for name, data in plugins.items():
        found = "yes" if data.get("found") else "no"
        version = data.get("version") or "unknown"
        source = data.get("source") or "unknown"
        print(f"  {name}: {found} | version: {version} | source: {source}")


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
