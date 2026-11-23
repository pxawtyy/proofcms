from __future__ import annotations

from typing import Any

from ..core.redact import redact_text, redact_url


def _index(report: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    indexed: dict[tuple[str, str], dict[str, Any]] = {}
    if not isinstance(report, dict):
        return indexed
    for target in report.get("targets", []) or []:
        if not isinstance(target, dict):
            continue
        target_url = str(target.get("target") or target.get("scan_base_url") or "")
        for finding in target.get("results", []) or []:
            if not isinstance(finding, dict):
                continue
            cve = str(finding.get("cve") or "")
            if cve:
                indexed[(target_url, cve)] = finding
    return indexed


def build_scan_diff(
    previous: dict[str, Any],
    current: dict[str, Any],
    previous_path: str = "",
) -> dict[str, Any]:
    """Return new/removed/status/version changes between two scan reports."""
    previous_index = _index(previous)
    current_index = _index(current)
    changes: list[dict[str, Any]] = []
    for target, cve in sorted(set(previous_index) | set(current_index)):
        old = previous_index.get((target, cve))
        new = current_index.get((target, cve))
        if old is None:
            change = "new"
        elif new is None:
            change = "removed"
        elif old.get("status") != new.get("status"):
            change = "status_changed"
        elif old.get("component_version") != new.get("component_version"):
            change = "version_changed"
        else:
            continue
        source = new or old or {}
        changes.append(
            {
                "change": change,
                "target": target,
                "cve": cve,
                "name": source.get("name") or cve,
                "component": source.get("component") or "",
                "previous_status": old.get("status") if old else None,
                "current_status": new.get("status") if new else None,
                "previous_version": old.get("component_version") if old else None,
                "current_version": new.get("component_version") if new else None,
                "detail": source.get("detail") or "",
            }
        )
    summary: dict[str, int] = {}
    for entry in changes:
        summary[entry["change"]] = summary.get(entry["change"], 0) + 1
    return {
        "previous_report": previous_path,
        "summary": summary,
        "changes": changes,
    }


def format_scan_diff(diff: dict[str, Any]) -> str:
    """Render a compact console summary of a scan diff."""
    changes = diff.get("changes") or []
    if not changes:
        return "Scan diff: no changes vs the previous report."
    lines = [f"Scan diff vs {redact_url(str(diff.get('previous_report') or 'previous report'))}:"]
    for change in changes:
        kind = change["change"]
        target = redact_url(str(change["target"]))
        component = redact_text(str(change["component"]))
        if kind == "status_changed":
            lines.append(
                f"  {target} {change['cve']} ({component}): "
                f"{change['previous_status']} -> {change['current_status']}"
            )
        elif kind == "version_changed":
            lines.append(
                f"  {target} {change['cve']} ({component}): "
                f"version {change['previous_version']} -> {change['current_version']}"
            )
        elif kind == "new":
            lines.append(
                f"  NEW {target} {change['cve']} ({component}): "
                f"{change['current_status']}"
            )
        else:
            lines.append(
                f"  REMOVED {target} {change['cve']} ({component}): "
                f"{change['previous_status']}"
            )
    return "\n".join(lines)
