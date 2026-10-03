from __future__ import annotations

import argparse
import importlib
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from proofcms.chains import AVAILABLE_CHAINS
from proofcms.core.http import (
    fetch_url,
    is_baseline_match,
    normalize_url,
    probe_target_baseline,
)
from proofcms.core.models import (
    CMSInfo,
    Confidence,
    CVECheckResult,
    Finding,
    JoomlaInfo,
    PluginInfo,
    Status,
)
from proofcms.detectors import (
    detect_baforms,
    detect_cms,
    detect_helix3,
    detect_helixultimate,
    detect_icagenda,
    detect_joomla,
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
    is_joomla_core_result,
    print_banner,
    print_chain_results,
    print_one_result,
    print_plugins,
    print_result,
    print_wordpress_inventory,
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
    "CMSInfo",
    "CVECheckResult",
    "Confidence",
    "Finding",
    "JoomlaInfo",
    "PluginInfo",
    "Status",
    "append_text_result",
    "detect_baforms",
    "detect_cms",
    "detect_helix3",
    "detect_helixultimate",
    "detect_icagenda",
    "detect_joomla",
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
    if selection.lower() in {"none", "no", "off"}:
        return []
    if selection.lower() == "all":
        return list(AVAILABLE_CVES)
    requested = [item.strip().upper() for item in selection.split(",") if item.strip()]
    unknown = [item for item in requested if item not in AVAILABLE_CVES]
    if unknown:
        raise SystemExit(f"Unknown CVE: {', '.join(unknown)}")
    return requested


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
    return list(dict.fromkeys(normalize_url(target, timeout=args.timeout, proxy=args.proxy) for target in targets))


def main():
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
        help="Optional lab-only command for aggressive blind RCE modules; CVE-2015-8562 defaults to uname -a.",
    )
    parser.add_argument("--timeout", type=int, default=12, help="HTTP timeout in seconds")
    parser.add_argument("--concurrency", type=int, default=5, help="Concurrency limit for detector probes. Default: 5")
    parser.add_argument("--proxy", help="Proxy URL passed to CVE modules")
    parser.add_argument("--json", dest="json_path", help="Write JSON report to this path")
    parser.add_argument("--report-dir", default=str(ROOT / "reports"), help="Directory for timestamped text reports")
    parser.add_argument("--no-text-report", action="store_true", help="Disable automatic timestamped text report")
    parser.add_argument("--show-patched", action="store_true", help="Show PATCHED CVEs in terminal and text report")
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

    targets = load_targets(args)
    if not targets:
        parser.print_help()
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

    start_time = datetime.now(timezone.utc)
    run_id = uuid.uuid4().hex[:8]

    # Calculate union of required detectors for the selected CVEs
    needed_detectors: set[str] = set()
    for cve_id in cves:
        module = importlib.import_module(AVAILABLE_CVES[cve_id])
        meta = getattr(module, "metadata", dict)()
        for det in meta.get("required_detectors", []):
            needed_detectors.add(det)

    targets_reports: list[dict] = []

    for target in targets:
        baseline = probe_target_baseline(target, timeout=args.timeout, proxy=args.proxy)
        info = detect_cms(target, args, baseline=baseline)
        php_runtime_info = detect_php_runtime(target, timeout=args.timeout, proxy=args.proxy)
        php_runtime = {
            "detected": php_runtime_info.detected,
            "version": php_runtime_info.version,
            "source": php_runtime_info.source,
            "server": php_runtime_info.server,
            "entrypoint": php_runtime_info.entrypoint,
        }
        plugins = (
            detect_plugins(
                target,
                args,
                baseline=baseline,
                required_plugins=needed_detectors,
                concurrency=args.concurrency,
            )
            if info.detected and info.name == "joomla"
            else {}
        )
        wordpress_inventory = (
            detect_wordpress_plugins(target, args.timeout, proxy=args.proxy, baseline=baseline)
            if info.detected and info.name == "wordpress"
            else {}
        )
        target_report = {
            "target": target,
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
            "results": [],
            "chains": [],
        }
        for cve_id in cves:
            module = importlib.import_module(AVAILABLE_CVES[cve_id])
            meta = getattr(module, "metadata", dict)()
            module_scope = meta.get("cms", "joomla")
            if module_scope not in {info.name, "php", "generic"}:
                continue
            run_exploit_check = cve_id in exploits
            selected_exploit_mode = (
                effective_exploit_mode(module, args.exploit_mode) if run_exploit_check else args.exploit_mode
            )
            try:
                result = module.check(
                    target,
                    info.version,
                    run_exploit_check=run_exploit_check,
                    timeout=args.timeout,
                    proxy=args.proxy,
                    exploit_mode=selected_exploit_mode,
                    aggressive_command=args.aggressive_command,
                    plugins=(wordpress_inventory.get("plugins", {}) if info.name == "wordpress" else plugins),
                    php_runtime=php_runtime,
                )
                result_dict = result.as_dict()
                result_dict["exploit_requested"] = run_exploit_check
                result_dict["requested_exploit_mode"] = selected_exploit_mode if run_exploit_check else None
                result_dict["requested_exploit_mode_input"] = args.exploit_mode if run_exploit_check else None
            except Exception as exc:  # noqa: BLE001 - isolate third-party probe failures per target
                result_dict = {
                    "cve": cve_id,
                    "name": meta.get("name", cve_id),
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
        for chain_id in chains:
            aggregate = AVAILABLE_CHAINS[chain_id]["aggregate"]
            target_report["chains"].append(aggregate(target_report["results"]))
        print_result(target, info, target_report["results"], show_patched=args.show_patched, php_runtime=php_runtime)
        print_chain_results(target_report["chains"])
        if info.detected and info.name == "joomla":
            print_plugins(plugins)
            print()
        elif info.detected and info.name == "wordpress":
            print_wordpress_inventory(wordpress_inventory)
            print()
        targets_reports.append(target_report)

    end_time = datetime.now(timezone.utc)
    duration = (end_time - start_time).total_seconds()

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
        for r in t.get("results", []):
            st = r.get("status", "ERROR")
            summary[st] = summary.get(st, 0) + 1

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
            "fail_on": args.fail_on,
            "command_provided": bool(args.aggressive_command),
        },
        "tls_policy": "insecure_skip_verify",
        "modules_loaded": list(AVAILABLE_CVES.keys()),
        "summary_by_status": summary,
        "targets": targets_reports,
    }

    if args.json_path:
        out = Path(args.json_path)
        write_json_report(out, full_report)
        print(f"JSON report saved to: {out}")

    if not args.no_text_report:
        stamp = start_time.strftime("%Y%m%d_%H%M%S_%f")
        out = Path(args.report_dir) / f"proofcms_{stamp}_{run_id}.txt"
        try:
            saved_out = write_text_report(out, full_report, sys.argv, show_patched=args.show_patched)
            print(f"Detailed report saved to: {saved_out}")
        except OSError as exc:
            fallback = Path(tempfile.gettempdir()) / "proofcms-reports" / f"proofcms_{stamp}_{run_id}.txt"
            try:
                saved_fallback = write_text_report(fallback, full_report, sys.argv, show_patched=args.show_patched)
                print(f"Warning: could not save the detailed report to {out}: {exc}")
                print(f"Detailed report saved to fallback path: {saved_fallback}")
            except OSError as fallback_exc:
                print(f"Warning: could not save the detailed report to {out}: {exc}")
                print(f"Warning: fallback also failed at {fallback}: {fallback_exc}")

    fail_criteria = {c.strip().lower() for c in args.fail_on.split(",") if c.strip()}
    if fail_criteria:
        if "vulnerable" in fail_criteria and (
            summary.get("VULNERABLE", 0) > 0 or summary.get("VULNERABLE_UPLOAD_ONLY", 0) > 0
        ):
            return 2
        if "likely" in fail_criteria and summary.get("LIKELY_VULNERABLE", 0) > 0:
            return 3
        if "inconclusive" in fail_criteria and summary.get("INCONCLUSIVE", 0) > 0:
            return 4
        if "error" in fail_criteria and summary.get("ERROR", 0) > 0:
            return 5

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
