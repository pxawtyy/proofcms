from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .console import (
    is_generic_web_result,
    is_joomla_core_result,
    is_php_runtime_result,
    is_wordpress_core_result,
    sanitize_argv,
    visible_results,
)


def append_text_result(lines: list[str], result: dict | Any):
    res = result if isinstance(result, dict) else result.as_dict()
    lines.append("-" * 80)
    lines.append(f"{res['cve']}: {res['status']} ({res['confidence']})")
    lines.append(f"Name       : {res.get('name')}")
    lines.append(f"Component  : {res.get('component')} {res.get('component_version') or 'unknown'}")
    lines.append(f"Rule       : {res.get('affected_rule')}")
    lines.append(f"Requested  : {'yes' if res.get('exploit_requested') else 'no'}")
    if res.get("exploit_requested"):
        lines.append(
            f"Mode       : input={res.get('requested_exploit_mode_input')} | "
            f"effective={res.get('requested_exploit_mode')}"
        )
    lines.append(f"Exploit ran: {'yes' if res.get('exploit_ran') else 'no'}")
    if res.get("proof_url"):
        lines.append(f"Proof URL  : {res.get('proof_url')}")
    if res.get("uploaded_filename"):
        cleanup_prefix = (
            "delete uploaded file"
            if res.get("status") in {"VULNERABLE", "VULNERABLE_UPLOAD_ONLY"}
            else "if present, delete uploaded file"
        )
        lines.append(f"Cleanup    : {cleanup_prefix} {res.get('uploaded_filename')}")
    if res.get("cleanup_attempted"):
        lines.append(f"Cleanup OK : {'yes' if res.get('cleanup_verified') else 'no'}")
    if res.get("evidence"):
        lines.append(f"Evidence   : {res.get('evidence')}")
    lines.append(f"Detail     : {res.get('detail')}")
    lines.append(f"Action     : {res.get('action')}")


def write_text_report(
    path: Path | str,
    report: dict,
    argv: list[str],
    show_patched: bool = False,
    tool_name: str = "ProofCMS",
):
    report_path = Path(path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    lines.append(f"{tool_name} detailed run report")
    lines.append("=" * 80)
    lines.append(f"Generated at: {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    lines.append(f"Command     : {' '.join(sanitize_argv(argv))}")
    lines.append("")
    for target in report.get("targets", []):
        cms = target.get("cms") or target.get("joomla", {})
        lines.append(f"Target: {target.get('target')}")
        lines.append(
            f"CMS: {cms.get('name') or 'unknown'} | detected: {'yes' if cms.get('detected') else 'no'} | "
            f"version: {cms.get('version') or 'unknown'} | source: {cms.get('source')}"
        )
        lines.append("")
        runtime = target.get("php") or {}
        lines.append(
            f"PHP: detected: {'yes' if runtime.get('detected') else 'no'} | "
            f"version: {runtime.get('version') or 'unknown'} | source: {runtime.get('source') or 'not-detected'}"
        )
        lines.append("")
        if cms.get("name") == "wordpress":
            wp = target.get("wordpress") or {}
            theme = wp.get("theme") or {}
            if theme.get("found"):
                lines.append("WordPress theme:")
                lines.append(
                    f"  - {theme.get('name')}: yes | version: {theme.get('version') or 'unknown'} | "
                    f"source: {theme.get('source') or 'unknown'}"
                )
            lines.append("WordPress plugins:")
            plugins = wp.get("plugins") or {}
            if plugins:
                for name, data in plugins.items():
                    lines.append(
                        f"  - {name}: yes | version: {data.get('version') or 'unknown'} | "
                        f"source: {data.get('source') or 'unknown'}"
                    )
            else:
                lines.append("  - none detected from public assets/probes")
        else:
            lines.append("Plugins/components:")
            for name, data in (target.get("plugins") or {}).items():
                lines.append(
                    f"  - {name}: {'yes' if data.get('found') else 'no'} | "
                    f"version: {data.get('version') or 'unknown'} | source: {data.get('source') or 'unknown'}"
                )
        lines.append("")
        results, hidden = visible_results(target.get("results", []), show_patched)
        php_results = [result for result in results if is_php_runtime_result(result)]
        generic_results = [result for result in results if is_generic_web_result(result)]
        cms_results = [result for result in results if not is_php_runtime_result(result) and not is_generic_web_result(result)]
        if cms.get("name") == "wordpress":
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
        lines.append("CVE results:")
        if hidden:
            lines.append(f"Note: {hidden} PATCHED result(s) hidden. Use --show-patched to include them.")
        for title, section_results in sections:
            if not section_results:
                continue
            lines.append("")
            lines.append(f"[{title}]")
            for result in section_results:
                append_text_result(lines, result)
        chains = target.get("chains", [])
        if chains:
            lines.append("")
            lines.append("[Attack chains]")
            for chain in chains:
                lines.append("-" * 80)
                lines.append(f"{chain.get('chain')}: {chain.get('status')} ({chain.get('confidence')})")
                lines.append(f"Components : {', '.join(chain.get('components', []))}")
                lines.append(f"Detail     : {chain.get('detail')}")
                lines.append(f"Action     : {chain.get('action')}")
        lines.append("")

    content = "\n".join(lines) + "\n"
    target_file = report_path
    counter = 1
    while True:
        try:
            with open(target_file, "x", encoding="utf-8") as fh:
                fh.write(content)
            break
        except FileExistsError:
            target_file = report_path.parent / f"{report_path.stem}_{counter}{report_path.suffix}"
            counter += 1
    return target_file
