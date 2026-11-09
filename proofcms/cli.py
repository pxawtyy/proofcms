from __future__ import annotations

import argparse
import importlib
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from proofcms.chains import AVAILABLE_CHAINS
from proofcms.core.args import parse_aggressive_args
from proofcms.core.categories import normalize_metadata
from proofcms.core.http import (
    configure_tls,
    fetch_url,
    is_baseline_match,
    normalize_url,
    probe_target_baseline,
    reset_transport_state,
)
from proofcms.core.models import (
    AspNetRuntimeInfo,
    CMSInfo,
    Confidence,
    CVECheckResult,
    Finding,
    JoomlaInfo,
    NginxRuntimeInfo,
    NodeRuntimeInfo,
    PluginInfo,
    Status,
)
from proofcms.detectors import (
    detect_aspnet_runtime,
    detect_baforms,
    detect_cms,
    detect_helix3,
    detect_helixultimate,
    detect_icagenda,
    detect_joomla,
    detect_nginx_runtime,
    detect_node_runtime,
    detect_pagebuilderck,
    detect_php_runtime,
    detect_rsfiles,
    detect_sppagebuilder,
    detect_wordpress,
    detect_wordpress_plugins,
    detect_wordpress_theme,
    joomla_signal_score,
    parse_wordpress_plugin_version,
    scan_joomla,
    validate_joomla_manifest,
    wordpress_signal_score,
)
from proofcms.detectors import (
    detect_joomla_plugins as detect_plugins,
)
from proofcms.reporting import (
    append_text_result,
    hidden_results_note,
    is_joomla_core_result,
    print_banner,
    print_chain_results,
    print_live_result,
    print_one_result,
    print_plugins,
    print_result,
    print_wordpress_inventory,
    redact_output,
    sanitize_argv,
    status_color,
    strip_ansi,
    visible_results,
    write_json_report,
    write_text_report,
)

__all__ = [
    "AVAILABLE_CVES",
    "TOOL_NAME",
    "AspNetRuntimeInfo",
    "CMSInfo",
    "CVECheckResult",
    "Confidence",
    "Finding",
    "JoomlaInfo",
    "NodeRuntimeInfo",
    "PluginInfo",
    "Status",
    "append_text_result",
    "detect_aspnet_runtime",
    "detect_baforms",
    "detect_cms",
    "detect_helix3",
    "detect_helixultimate",
    "detect_icagenda",
    "detect_joomla",
    "detect_nginx_runtime",
    "detect_node_runtime",
    "detect_pagebuilderck",
    "detect_plugins",
    "detect_rsfiles",
    "detect_sppagebuilder",
    "detect_wordpress",
    "detect_wordpress_plugins",
    "detect_wordpress_theme",
    "fetch_url",
    "is_baseline_match",
    "is_joomla_core_result",
    "joomla_signal_score",
    "main",
    "normalize_url",
    "parse_wordpress_plugin_version",
    "print_banner",
    "print_live_result",
    "print_one_result",
    "print_plugins",
    "print_result",
    "print_wordpress_inventory",
    "probe_target_baseline",
    "sanitize_argv",
    "scan_joomla",
    "status_color",
    "strip_ansi",
    "validate_joomla_manifest",
    "visible_results",
    "wordpress_signal_score",
    "write_json_report",
    "write_text_report",
]


TOOL_NAME = "ProofCMS"
ROOT = Path(__file__).resolve().parent.parent

from proofcms.modules.generic import AVAILABLE_CVES as GENERIC_CVES
from proofcms.modules.joomla import AVAILABLE_CVES as JOOMLA_CVES
from proofcms.modules.php import AVAILABLE_CVES as PHP_CVES
from proofcms.modules.wordpress import AVAILABLE_CVES as WORDPRESS_CVES

AVAILABLE_CVES = {**JOOMLA_CVES, **WORDPRESS_CVES, **PHP_CVES, **GENERIC_CVES}


def print_cve_catalog():
    from proofcms.reporting import print_cve_catalog as _core_catalog

    _core_catalog(AVAILABLE_CVES, AVAILABLE_CHAINS)


def selected_cves(selection: str) -> list[str]:
    selection = selection.strip()
    if selection.lower() in {"none", "no", "off"}:
        return []
    if selection.lower() == "all":
        return list(AVAILABLE_CVES)
    requested = [item.strip().upper() for item in selection.split(",") if item.strip()]
    unknown = [item for item in requested if item not in AVAILABLE_CVES]
    if unknown:
        raise SystemExit(f"Unknown CVE: {', '.join(unknown)}")
    return list(dict.fromkeys(requested))


def exploit_selection(value: str) -> set[str]:
    value = value.strip()
    if value.lower() in {"none", "no", "off"}:
        return set()
    if value.lower() == "all":
        return set(AVAILABLE_CVES)
    chosen = selected_cves(value)
    return set(chosen)


def selected_chains(selection: str) -> list[str]:
    if selection.strip().lower() in {"", "none", "no", "off"}:
        return []
    if selection.strip().lower() == "all":
        return list(AVAILABLE_CHAINS)
    requested = [item.strip().lower() for item in selection.split(",") if item.strip()]
    unknown = [item for item in requested if item not in AVAILABLE_CHAINS]
    if unknown:
        raise SystemExit(f"Unknown attack chain: {', '.join(unknown)}")
    return requested


def effective_exploit_mode(module, requested_mode: str) -> str:
    if requested_mode != "auto":
        return requested_mode
    modes = module.metadata().get("exploit_modes", [])
    # In auto mode, select the least intrusive mode capable of producing evidence
    if "safe" in modes:
        return "safe"
    if "aggressive" in modes:
        return "aggressive"
    return "safe"


def selection_needs_lab(exploits: set[str], requested_mode: str) -> bool:
    if requested_mode == "aggressive":
        return bool(exploits)
    if requested_mode != "auto":
        return False
    # In auto mode, lab authorization is only needed if an exploit module ONLY offers aggressive mode
    for cve_id in exploits:
        module = importlib.import_module(AVAILABLE_CVES[cve_id])
        modes = module.metadata().get("exploit_modes", [])
        if "aggressive" in modes and "safe" not in modes:
            return True
    return False


def load_targets(args) -> list[str]:
    targets: list[str] = []
    if args.url:
        targets.append(args.url)
    if args.list:
        with open(args.list, "r", encoding="utf-8") as fh:
            targets.extend(line.strip() for line in fh if line.strip())
    return list(dict.fromkeys(normalize_url(target) for target in targets))


def cleanup_capable_cves() -> list[str]:
    """Return sorted CVE IDs whose module exposes a compatible ``cleanup`` hook."""
    import inspect

    capable = []
    for cve_id, module_path in AVAILABLE_CVES.items():
        try:
            module = importlib.import_module(module_path)
        except Exception:  # noqa: BLE001, S112 - skip unloadable modules, keep scanning
            continue
        hook = getattr(module, "cleanup", None)
        if not callable(hook):
            continue
        try:
            params = inspect.signature(hook).parameters
        except (TypeError, ValueError):
            continue
        names = list(params)
        if not names or names[0] != "target_url":
            continue
        if "aggressive_args" not in params and not any(
            p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()
        ):
            continue
        capable.append(cve_id)
    return sorted(capable)


def run_lab_cleanup(args, targets: list[str], aggressive_args: dict) -> int:
    """Execute ``module.cleanup()`` for one CVE across targets; no scanning."""
    cve_id = (args.lab_cleanup or "").strip().upper()
    if cve_id not in AVAILABLE_CVES:
        print(f"Error: unknown CVE for --lab-cleanup: {args.lab_cleanup!r}.")
        return 2
    module = importlib.import_module(AVAILABLE_CVES[cve_id])
    hook = getattr(module, "cleanup", None)
    if not callable(hook):
        print(f"Error: {cve_id} has no automated lab-cleanup hook.")
        print(f"Modules with cleanup hooks: {', '.join(cleanup_capable_cves()) or 'none'}.")
        return 2
    if not args.i_understand_authorized or not args.i_understand_lab_only:
        print("Error: --lab-cleanup changes lab state and requires --i-understand-authorized --i-understand-lab-only.")
        return 2
    failures = 0
    for target in targets:
        reset_transport_state()
        try:
            result = hook(
                target,
                timeout=args.timeout,
                proxy=args.proxy,
                aggressive_args=aggressive_args,
                aggressive_command=args.aggressive_command,
            )
        except Exception as exc:  # noqa: BLE001 - isolate cleanup failures per target
            print(f"[{target}] {cve_id} cleanup ERROR: {type(exc).__name__}: {exc}")
            failures += 1
            continue
        shown = redact_output(dict(result))
        print(f"[{target}] {cve_id} cleanup ok={shown.get('ok')}: {shown.get('detail')}")
        for path in shown.get("removed") or []:
            print(f"  removed: {path}")
        for path in shown.get("remaining") or []:
            print(f"  remaining: {path}")
            failures += 1
        for step in shown.get("manual") or []:
            print(f"  manual: {step}")
            failures += 1
    return 2 if failures else 0


def main():
    monotonic_start = time.monotonic()
    start_time = datetime.now(timezone.utc)
    parser = argparse.ArgumentParser(description=f"{TOOL_NAME} - CMS vulnerability validation hub")
    parser.add_argument("-u", "--url", help="Single target URL")
    parser.add_argument("-l", "--list", help="File with one target URL per line")
    parser.add_argument(
        "--cms",
        choices=["auto", "joomla", "wordpress"],
        default="auto",
        help="CMS detection mode. Default: auto",
    )
    parser.add_argument(
        "--cve",
        default=None,
        help="CVE to check, comma-list, all, or none. Defaults to all unless --chain is used.",
    )
    parser.add_argument("--chain", default="none", help="Named attack chain to assess, comma-list, or all")
    parser.add_argument(
        "--run-exploit",
        default="none",
        help="Run optional exploit proof for one CVE, comma-list, or all. Default: none",
    )
    parser.add_argument(
        "--exploit-mode",
        choices=["safe", "aggressive", "auto"],
        default="safe",
        help=(
            "Exploit mode. safe = controlled audit proof; aggressive = lab-only blind RCE/legacy PoC; "
            "auto = prefers safe for modules with safe mode, and aggressive only when safe is not available."
        ),
    )
    parser.add_argument(
        "--run-all-lab-probes",
        action="store_true",
        help="Lab-only convenience shortcut: enables aggressive exploit execution on all capable modules.",
    )
    parser.add_argument(
        "--lab-cleanup",
        default=None,
        metavar="CVE-ID",
        help=(
            "Run the lab-cleanup hook for one CVE instead of scanning "
            "(removes proofcms-* leftovers via the module's known patterns; "
            "requires --i-understand-authorized --i-understand-lab-only)."
        ),
    )
    parser.add_argument(
        "--i-understand-authorized",
        action="store_true",
        help="Required for safe or aggressive exploit checks. Confirms authorization.",
    )
    parser.add_argument(
        "--i-understand-lab-only",
        action="store_true",
        help="Required for aggressive probes, including --exploit-mode aggressive or auto when needed.",
    )
    parser.add_argument(
        "--aggressive-command",
        help=(
            "Optional lab-only command for aggressive blind RCE modules; CVE-2015-8562 defaults to uname -a. "
            "Prefer repeatable --aggressive-arg KEY=VALUE; legacy formats still work."
        ),
    )
    parser.add_argument(
        "--aggressive-arg",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help=(
            "Named lab-only argument for aggressive probes (repeatable). "
            "Keys: admin_user/admin_password (15882, 90915), canary_url/cache_group (90915), "
            "page_url/username (32243), hash/full (28000). Example: --aggressive-arg admin_user=admin"
        ),
    )
    parser.add_argument("--timeout", type=int, default=12, help="HTTP timeout in seconds")
    parser.add_argument("--concurrency", type=int, default=5, help="Concurrency limit for detector probes. Default: 5")
    parser.add_argument(
        "--inventory",
        choices=["full", "required"],
        default="full",
        help="Joomla inventory scope: full or only detectors required by selected checks.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification for isolated lab targets.",
    )
    parser.add_argument("--proxy", help="Proxy URL passed to CVE modules")
    parser.add_argument("--json", dest="json_path", help="Write JSON report to this path")
    parser.add_argument("--overwrite-json", action="store_true", help="Replace an existing --json report atomically")
    parser.add_argument("--report-dir", default=str(ROOT / "reports"), help="Directory for timestamped text reports")
    parser.add_argument("--no-text-report", action="store_true", help="Disable automatic timestamped text report")
    parser.add_argument("--show-patched", action="store_true", help="Show PATCHED CVEs in terminal and text report")
    parser.add_argument(
        "--show-not-detected",
        action="store_true",
        help="Show NOT_DETECTED CVEs and undetected plugin inventory entries",
    )
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="Show all CVE results and plugin inventory entries, including PATCHED and NOT_DETECTED",
    )
    parser.add_argument(
        "--fail-on",
        default="",
        help=(
            "Comma-separated statuses that cause CLI to exit with non-zero code. "
            "Supported: vulnerable, likely, inconclusive, error. Example: --fail-on vulnerable,error"
        ),
    )
    parser.add_argument(
        "--list-cves", action="store_true", help="List available CVE modules and attack chains, then exit"
    )
    args = parser.parse_args()

    print_banner()

    if args.list_cves:
        print_cve_catalog()
        return 0

    if args.run_all_lab_probes:
        args.run_exploit = "all"
        args.exploit_mode = "aggressive"

    try:
        aggressive_args = parse_aggressive_args(args.aggressive_arg)
    except ValueError as exc:
        print(f"Error: {exc}")
        return 2

    chains = selected_chains(args.chain)
    cves = selected_cves(args.cve or ("none" if chains else "all"))
    for chain_id in chains:
        for cve_id in AVAILABLE_CHAINS[chain_id]["cves"]:
            if cve_id not in cves:
                cves.append(cve_id)
    exploits = set(cves) if args.run_exploit.strip().lower() == "all" else exploit_selection(args.run_exploit)

    # Validate that requested exploits are among selected CVEs
    if exploits:
        cves_set = set(cves)
        unselected_exploits = [exp for exp in sorted(exploits) if exp not in cves_set]
        if unselected_exploits:
            print(
                f"Error: exploit(s) {', '.join(unselected_exploits)} requested with --run-exploit "
                f"are not included in the selected CVEs (--cve {args.cve})."
            )
            return 2

    if exploits and not args.i_understand_authorized:
        print("Error: --run-exploit requires --i-understand-authorized to confirm authorization.")
        return 2
    if exploits and selection_needs_lab(exploits, args.exploit_mode) and not args.i_understand_lab_only:
        print("Error: this exploit selection includes aggressive mode and requires --i-understand-lab-only.")
        print("Use aggressive mode only in an isolated lab you control.")
        return 2

    fail_criteria = {c.strip().lower() for c in args.fail_on.split(",") if c.strip()}
    supported_fail_criteria = {"vulnerable", "likely", "inconclusive", "error"}
    unknown_fail_criteria = sorted(fail_criteria - supported_fail_criteria)
    if unknown_fail_criteria:
        print(f"Error: unsupported --fail-on value(s): {', '.join(unknown_fail_criteria)}")
        return 1
    if args.timeout <= 0:
        print("Error: --timeout must be greater than zero.")
        return 1
    if args.concurrency <= 0:
        print("Error: --concurrency must be greater than zero.")
        return 1

    configure_tls(verify=not args.insecure)
    try:
        targets = load_targets(args)
    except (OSError, ValueError) as exc:
        print(f"Error: could not load targets: {exc}")
        return 1
    if not targets:
        parser.print_help()
        return 1

    if args.lab_cleanup:
        return run_lab_cleanup(args, targets, aggressive_args)

    run_id = uuid.uuid4().hex[:8]

    # Calculate union of required detectors for the selected CVEs
    needed_detectors: set[str] = set()
    module_setup_errors: dict[str, str] = {}
    for cve_id in cves:
        try:
            module = importlib.import_module(AVAILABLE_CVES[cve_id])
            meta = normalize_metadata(getattr(module, "metadata", dict)())
            for det in meta.get("required_detectors", []):
                needed_detectors.add(det)
        except Exception as exc:  # noqa: BLE001
            module_setup_errors[cve_id] = f"{type(exc).__name__}: {exc}"

    targets_reports: list[dict] = []

    for target in targets:
        target_started = time.monotonic()
        reset_transport_state()
        target_errors: list[str] = []
        try:
            baseline = probe_target_baseline(target, timeout=args.timeout, proxy=args.proxy)
        except Exception as exc:  # noqa: BLE001
            baseline = {"status": 0, "target_root": target, "error": {"type": type(exc).__name__, "message": str(exc)}}
            target_errors.append(f"Baseline detection failed: {type(exc).__name__}: {exc}")
        if baseline.get("status", 0) == 0:
            message = "Target baseline request failed; CMS and component absence cannot be established."
            if message not in target_errors:
                target_errors.append(message)
            baseline_error = baseline.get("error")
            if isinstance(baseline_error, dict):
                error_type = baseline_error.get("type", "transport error")
                error_message = baseline_error.get("message", "")
                diagnostic = f"Baseline transport: {error_type}"
                if error_message:
                    diagnostic += f": {error_message}"
                if diagnostic not in target_errors:
                    target_errors.append(diagnostic)
        if baseline.get("edge_interstitial"):
            print(
                f"Warning: {target} returned a {baseline['edge_interstitial']} challenge page. "
                "CMS and vulnerability results may describe the edge page rather than the origin."
            )
        try:
            info = detect_cms(target, args, baseline=baseline)
        except Exception as exc:  # noqa: BLE001
            target_errors.append(f"CMS detection failed: {type(exc).__name__}: {exc}")
            info = CMSInfo("unknown", False, None, "error")
        operational_target = info.base_url or target
        try:
            nginx_runtime_info = detect_nginx_runtime(operational_target, timeout=args.timeout, proxy=args.proxy)
        except Exception as exc:  # noqa: BLE001
            target_errors.append(f"NGINX detection failed: {type(exc).__name__}: {exc}")
            nginx_runtime_info = NginxRuntimeInfo(False, None, "error")
        try:
            node_runtime_info = detect_node_runtime(operational_target, timeout=args.timeout, proxy=args.proxy)
        except Exception as exc:  # noqa: BLE001
            target_errors.append(f"Node.js detection failed: {type(exc).__name__}: {exc}")
            node_runtime_info = NodeRuntimeInfo(False, None, "error")
        nginx_runtime = {
            "detected": nginx_runtime_info.detected,
            "version": nginx_runtime_info.version,
            "source": nginx_runtime_info.source,
            "server": nginx_runtime_info.server,
            "http3_advertised": nginx_runtime_info.http3_advertised,
            "edge_server": nginx_runtime_info.edge_server,
            "edge_http3_advertised": nginx_runtime_info.edge_http3_advertised,
        }
        node_runtime = {
            "detected": node_runtime_info.detected,
            "version": node_runtime_info.version,
            "source": node_runtime_info.source,
            "server": node_runtime_info.server,
            "framework": node_runtime_info.framework,
            "session_cookie": node_runtime_info.session_cookie,
        }
        try:
            php_runtime_info = detect_php_runtime(operational_target, timeout=args.timeout, proxy=args.proxy)
        except Exception as exc:  # noqa: BLE001
            target_errors.append(f"PHP detection failed: {type(exc).__name__}: {exc}")
            from proofcms.core.models import PHPRuntimeInfo

            php_runtime_info = PHPRuntimeInfo(False, None, "error")
        try:
            aspnet_runtime_info = detect_aspnet_runtime(operational_target, timeout=args.timeout, proxy=args.proxy)
        except Exception as exc:  # noqa: BLE001
            target_errors.append(f"ASP.NET/GeneXus detection failed: {type(exc).__name__}: {exc}")
            aspnet_runtime_info = AspNetRuntimeInfo(False, None, "error")
        php_runtime = {
            "detected": php_runtime_info.detected,
            "version": php_runtime_info.version,
            "source": php_runtime_info.source,
            "server": php_runtime_info.server,
            "entrypoint": php_runtime_info.entrypoint,
            "phpinfo_exposed": php_runtime_info.phpinfo_exposed,
            "phpinfo_path": php_runtime_info.phpinfo_path,
            "phpinfo_size": php_runtime_info.phpinfo_size,
            "origin_ip": php_runtime_info.origin_ip,
            "origin_reachable": php_runtime_info.origin_reachable,
            "origin_server": php_runtime_info.origin_server,
        }
        aspnet_runtime = {
            "detected": aspnet_runtime_info.detected,
            "version": aspnet_runtime_info.version,
            "source": aspnet_runtime_info.source,
            "server": aspnet_runtime_info.server,
            "session_cookie": aspnet_runtime_info.session_cookie,
            "session_secure": aspnet_runtime_info.session_secure,
            "session_samesite": aspnet_runtime_info.session_samesite,
            "genexus_detected": aspnet_runtime_info.genexus_detected,
            "genexus_version": aspnet_runtime_info.genexus_version,
            "genexus_generator": aspnet_runtime_info.genexus_generator,
            "genexus_dbms": aspnet_runtime_info.genexus_dbms,
            "genexus_source": aspnet_runtime_info.genexus_source,
        }
        try:
            plugins = (
                detect_plugins(
                    operational_target,
                    args,
                    baseline=baseline,
                    required_plugins=needed_detectors,
                    concurrency=args.concurrency,
                )
                if info.detected and info.name == "joomla"
                else {}
            )
        except Exception as exc:  # noqa: BLE001
            plugins = {}
            target_errors.append(f"Joomla inventory failed: {type(exc).__name__}: {exc}")
        try:
            wordpress_inventory = (
                detect_wordpress_plugins(operational_target, args.timeout, proxy=args.proxy, baseline=baseline)
                if info.detected and info.name == "wordpress"
                else {}
            )
        except Exception as exc:  # noqa: BLE001
            wordpress_inventory = {}
            target_errors.append(f"WordPress inventory failed: {type(exc).__name__}: {exc}")
        for inventory_error in wordpress_inventory.get("errors", []):
            target_errors.append(f"WordPress inventory failed: {inventory_error}")
        target_report = {
            "target": target,
            "scan_base_url": operational_target,
            "cms": {
                "name": info.name,
                "detected": info.detected,
                "version": info.version,
                "source": info.source,
            },
            "joomla": {
                "detected": info.detected and info.name == "joomla",
                "version": info.version if info.name == "joomla" else None,
                "source": info.source if info.name == "joomla" else "not-detected",
            },
            "plugins": plugins,
            "wordpress": wordpress_inventory,
            "php": php_runtime,
            "nginx": nginx_runtime,
            "node": node_runtime,
            "aspnet": aspnet_runtime,
            "genexus": {
                "detected": aspnet_runtime_info.genexus_detected,
                "version": aspnet_runtime_info.genexus_version,
                "generator": aspnet_runtime_info.genexus_generator,
                "dbms": aspnet_runtime_info.genexus_dbms,
                "source": aspnet_runtime_info.genexus_source,
            },
            "results": [],
            "chains": [],
            "edge_interstitial": baseline.get("edge_interstitial"),
            "errors": target_errors,
            "selected_modules": list(cves),
        }
        print_result(
            target,
            info,
            [],
            show_patched=args.show_patched,
            show_not_detected=args.show_not_detected,
            show_all=args.show_all,
            php_runtime=php_runtime,
            nginx_runtime=nginx_runtime,
            node_runtime=node_runtime,
            aspnet_runtime=aspnet_runtime,
            errors=target_errors,
        )
        if php_runtime_info.phpinfo_exposed:
            target_report["results"].append(
                Finding(
                    "PROOFCMS-PHPINFO-EXPOSURE",
                    "Public phpinfo() disclosure",
                    Status.VULNERABLE,
                    Confidence.CONFIRMED,
                    "PHP runtime",
                    php_runtime_info.version,
                    "Public phpinfo.php endpoint returns a phpinfo() document",
                    detail=(
                        f"{php_runtime_info.phpinfo_path or '/phpinfo.php'} returned a phpinfo() document "
                        f"({php_runtime_info.phpinfo_size or 'unknown'} bytes), disclosing runtime and server configuration."
                        + (
                            " PHP 7.4 is end-of-life and no longer receives upstream security fixes."
                            if (php_runtime_info.version or "").startswith("7.4.")
                            else ""
                        )
                    ),
                    action="Remove phpinfo.php from the production document root and rotate any exposed infrastructure secrets.",
                    proof_url=f"{operational_target.rstrip('/')}{php_runtime_info.phpinfo_path or '/phpinfo.php'}",
                    evidence={
                        "path": php_runtime_info.phpinfo_path or "/phpinfo.php",
                        "response_bytes": php_runtime_info.phpinfo_size,
                        "origin_ip_disclosed": bool(php_runtime_info.origin_ip),
                    },
                    vulnerability_type="Information Disclosure",
                ).as_dict()
            )
            print_live_result(
                target_report["results"][-1], args.show_patched, args.show_not_detected, args.show_all
            )
        if php_runtime_info.origin_reachable:
            target_report["results"].append(
                Finding(
                    "PROOFCMS-ORIGIN-DIRECT-ACCESS",
                    "Direct origin access bypasses the edge",
                    Status.VULNERABLE,
                    Confidence.CONFIRMED,
                    "Origin infrastructure",
                    None,
                    "A globally routable origin address disclosed by the target accepts direct HTTP requests",
                    detail=f"The disclosed origin address answered directly with Server: {php_runtime_info.origin_server or 'unknown'}.",
                    action="Restrict the origin firewall to trusted edge-provider ranges and reject direct public access.",
                    evidence={
                        "origin_ip": php_runtime_info.origin_ip,
                        "origin_server": php_runtime_info.origin_server,
                    },
                    vulnerability_type="Improper Access Control",
                ).as_dict()
            )
            print_live_result(
                target_report["results"][-1], args.show_patched, args.show_not_detected, args.show_all
            )
        for cve_id in cves:
            if cve_id in module_setup_errors:
                setup_error = {
                    "cve": cve_id,
                    "name": cve_id,
                    "vulnerability_type": "Other",
                    "component": "Unknown",
                    "component_version": None,
                    "affected_rule": "unknown",
                    "status": "ERROR",
                    "confidence": "LOW",
                    "detail": f"Module setup failed: {module_setup_errors[cve_id]}",
                    "action": "Check module integrity.",
                    "exploit_available": False,
                }
                target_report["results"].append(setup_error)
                print_live_result(setup_error, args.show_patched, args.show_not_detected, args.show_all)
                continue
            module = importlib.import_module(AVAILABLE_CVES[cve_id])
            meta = normalize_metadata(getattr(module, "metadata", dict)())
            module_scope = meta.get("cms", "joomla")
            if module_scope not in {info.name, "php", "generic"}:
                continue
            run_exploit_check = cve_id in exploits
            selected_exploit_mode = (
                effective_exploit_mode(module, args.exploit_mode) if run_exploit_check else args.exploit_mode
            )
            try:
                result = module.check(
                    operational_target,
                    info.version,
                    run_exploit_check=run_exploit_check,
                    timeout=args.timeout,
                    proxy=args.proxy,
                    exploit_mode=selected_exploit_mode,
                    aggressive_command=args.aggressive_command,
                    aggressive_args=aggressive_args,
                    plugins=(wordpress_inventory.get("plugins", {}) if info.name == "wordpress" else plugins),
                    php_runtime=php_runtime,
                    nginx_runtime=nginx_runtime,
                    node_runtime=node_runtime,
                    aspnet_runtime=aspnet_runtime,
                )
                result_dict = result.as_dict()
                result_dict["exploit_requested"] = run_exploit_check
                result_dict["requested_exploit_mode"] = selected_exploit_mode if run_exploit_check else None
                result_dict["requested_exploit_mode_input"] = args.exploit_mode if run_exploit_check else None
            except Exception as exc:  # noqa: BLE001 - isolate third-party probe failures per target
                result_dict = {
                    "cve": cve_id,
                    "name": meta.get("name", cve_id),
                    "vulnerability_type": meta.get("vulnerability_type", "Other"),
                    "component": meta.get("component", "Unknown"),
                    "component_version": None,
                    "affected_rule": meta.get("affected_rule", "unknown"),
                    "status": "ERROR",
                    "confidence": "LOW",
                    "detail": f"Unexpected module error: {type(exc).__name__}: {exc}",
                    "action": "Check module integrity and target connectivity.",
                    "exploit_available": meta.get("exploit_available", False),
                    "exploit_ran": False,
                    "exploit_requested": run_exploit_check,
                    "requested_exploit_mode": selected_exploit_mode if run_exploit_check else None,
                    "requested_exploit_mode_input": args.exploit_mode if run_exploit_check else None,
                }
            target_report["results"].append(result_dict)
            print_live_result(result_dict, args.show_patched, args.show_not_detected, args.show_all)
        for chain_id in chains:
            try:
                aggregate = AVAILABLE_CHAINS[chain_id]["aggregate"]
                target_report["chains"].append(aggregate(target_report["results"]))
            except Exception as exc:  # noqa: BLE001
                target_report["chains"].append({
                    "chain": chain_id,
                    "status": "ERROR",
                    "confidence": "LOW",
                    "components": AVAILABLE_CHAINS[chain_id].get("cves", []),
                    "detail": f"Chain aggregation failed: {type(exc).__name__}: {exc}",
                    "action": "Check chain integrity.",
                })
        _, hidden = visible_results(
            target_report["results"], args.show_patched, args.show_not_detected, args.show_all
        )
        hidden_note = hidden_results_note(hidden)
        if hidden_note:
            print(f"({hidden_note})\n")
        print_chain_results(target_report["chains"])
        if info.detected and info.name == "joomla":
            print_plugins(
                plugins,
                show_not_detected=args.show_not_detected,
                show_all=args.show_all,
            )
            print()
        elif info.detected and info.name == "wordpress":
            print_wordpress_inventory(wordpress_inventory)
            print()
        target_report["duration_seconds"] = round(time.monotonic() - target_started, 3)
        targets_reports.append(target_report)

    end_time = datetime.now(timezone.utc)
    duration = time.monotonic() - monotonic_start

    summary = {
        "VULNERABLE": 0,
        "VULNERABLE_UPLOAD_ONLY": 0,
        "LIKELY_VULNERABLE": 0,
        "INCONCLUSIVE": 0,
        "BLOCKED_EXTERNAL": 0,
        "NOT_AFFECTED": 0,
        "NOT_DETECTED": 0,
        "ERROR": 0,
    }
    for t in targets_reports:
        if t.get("errors"):
            summary["ERROR"] += len(t["errors"])
        for r in t.get("results", []):
            st = r.get("status", "ERROR")
            summary[st] = summary.get(st, 0) + 1
    chain_summary: dict[str, int] = {}
    for target_report in targets_reports:
        for chain in target_report.get("chains", []):
            status = chain.get("status", "ERROR")
            chain_summary[status] = chain_summary.get(status, 0) + 1

    full_report = {
        "schema_version": "2.1.0",
        "tool": TOOL_NAME,
        "tool_version": "2.1.0",
        "run_id": run_id,
        "started_at": start_time.isoformat(),
        "finished_at": end_time.isoformat(),
        "duration_seconds": round(duration, 3),
        "options": {
            "cms": args.cms,
            "cve": args.cve,
            "chain": args.chain,
            "run_exploit": args.run_exploit,
            "exploit_mode": args.exploit_mode,
            "timeout": args.timeout,
            "proxy": "***" if args.proxy else None,
            "concurrency": args.concurrency,
            "inventory": args.inventory,
            "fail_on": args.fail_on,
            "command_provided": bool(args.aggressive_command),
            "aggressive_args_provided": sorted(aggressive_args),
            "show_patched": args.show_patched,
            "show_not_detected": args.show_not_detected,
            "show_all": args.show_all,
        },
        "tls_policy": "insecure_skip_verify" if args.insecure else "verify",
        "modules_selected": cves,
        "modules_setup_failed": module_setup_errors,
        "summary_by_status": summary,
        "summary_by_chain_status": chain_summary,
        "targets": targets_reports,
    }

    report_write_error = False
    if args.json_path:
        out = Path(args.json_path)
        try:
            saved_json = write_json_report(out, full_report, overwrite=args.overwrite_json)
            print(f"JSON report saved to: {saved_json}")
        except OSError as exc:
            print(f"Error: could not save JSON report to {out}: {exc}")
            summary["ERROR"] += 1
            report_write_error = True

    if not args.no_text_report:
        stamp = start_time.strftime("%Y%m%d_%H%M%S_%f")
        out = Path(args.report_dir) / f"proofcms_{stamp}_{run_id}.txt"
        try:
            saved_out = write_text_report(
                out,
                full_report,
                sys.argv,
                show_patched=args.show_patched,
                show_not_detected=args.show_not_detected,
                show_all=args.show_all,
            )
            print(f"Detailed report saved to: {saved_out}")
        except OSError as exc:
            fallback = Path(tempfile.gettempdir()) / "proofcms-reports" / f"proofcms_{stamp}_{run_id}.txt"
            try:
                saved_fallback = write_text_report(
                    fallback,
                    full_report,
                    sys.argv,
                    show_patched=args.show_patched,
                    show_not_detected=args.show_not_detected,
                    show_all=args.show_all,
                )
                print(f"Warning: could not save the detailed report to {out}: {exc}")
                print(f"Detailed report saved to fallback path: {saved_fallback}")
            except OSError as fallback_exc:
                print(f"Warning: could not save the detailed report to {out}: {exc}")
                print(f"Warning: fallback also failed at {fallback}: {fallback_exc}")
                report_write_error = True

    if fail_criteria:
        if "vulnerable" in fail_criteria and (
            summary.get("VULNERABLE", 0) > 0 or summary.get("VULNERABLE_UPLOAD_ONLY", 0) > 0
            or chain_summary.get("VULNERABLE", 0) > 0
        ):
            return 2
        if "likely" in fail_criteria and (
            summary.get("LIKELY_VULNERABLE", 0) > 0 or chain_summary.get("LIKELY_VULNERABLE", 0) > 0
        ):
            return 3
        if "inconclusive" in fail_criteria and (
            summary.get("INCONCLUSIVE", 0) > 0
            or summary.get("DETECTED_VERSION_UNKNOWN", 0) > 0
            or summary.get("BLOCKED_EXTERNAL", 0) > 0
            or chain_summary.get("INCONCLUSIVE", 0) > 0
            or chain_summary.get("BLOCKED_EXTERNAL", 0) > 0
        ):
            return 4
        if "error" in fail_criteria and (
            summary.get("ERROR", 0) > 0 or chain_summary.get("ERROR", 0) > 0
        ):
            return 5

    return 1 if report_write_error else 0


if __name__ == "__main__":
    raise SystemExit(main())
