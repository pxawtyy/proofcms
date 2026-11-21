from __future__ import annotations

from typing import Any

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"


def _kind_and_level(status: str) -> tuple[str, str]:
    if status in {"VULNERABLE", "VULNERABLE_UPLOAD_ONLY"}:
        return "fail", "error"
    if status in {
        "LIKELY_VULNERABLE",
        "INCONCLUSIVE",
        "NOT_CONFIRMED",
        "BLOCKED_EXTERNAL",
        "ERROR",
        "DETECTED_VERSION_UNKNOWN",
    }:
        return "review", "warning"
    if status == "NOT_DETECTED":
        return "notApplicable", "note"
    return "pass", "note"


def build_sarif_report(report: dict[str, Any]) -> dict[str, Any]:
    """Convert a ProofCMS JSON report into a SARIF 2.1.0 document."""
    rules: dict[str, dict[str, Any]] = {}
    rule_indices: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    for target in report.get("targets", []) or []:
        target_url = str(target.get("scan_base_url") or target.get("target") or "")
        for finding in target.get("results", []) or []:
            cve = str(finding.get("cve") or "UNKNOWN")
            if cve not in rules:
                rule_indices[cve] = len(rules)
                rule: dict[str, Any] = {
                    "id": cve,
                    "name": str(finding.get("name") or cve),
                    "shortDescription": {"text": str(finding.get("name") or cve)},
                    "fullDescription": {"text": str(finding.get("affected_rule") or "")},
                    "properties": {
                        "vulnerability_type": finding.get("vulnerability_type") or "Other",
                        "component": finding.get("component") or "",
                    },
                }
                if cve.startswith("CVE-"):
                    rule["helpUri"] = f"https://www.cve.org/CVERecord?id={cve}"
                rules[cve] = rule
            kind, level = _kind_and_level(str(finding.get("status") or "ERROR"))
            result: dict[str, Any] = {
                "ruleId": cve,
                "ruleIndex": rule_indices[cve],
                "kind": kind,
                "level": level,
                "message": {
                    "text": (
                        f"{finding.get('name') or cve}: "
                        f"{finding.get('detail') or finding.get('status') or 'unknown'}"
                    )
                },
                "properties": {
                    "status": finding.get("status"),
                    "confidence": finding.get("confidence"),
                    "component": finding.get("component"),
                    "component_version": finding.get("component_version"),
                    "exploit_available": finding.get("exploit_available"),
                    "exploit_ran": finding.get("exploit_ran"),
                    "vulnerability_type": finding.get("vulnerability_type"),
                    "evidence": finding.get("evidence"),
                },
            }
            if target_url:
                result["locations"] = [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": target_url},
                            "region": {"startLine": 1},
                        }
                    }
                ]
            results.append(result)

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": str(report.get("tool") or "ProofCMS"),
                "version": str(report.get("tool_version") or "2.1.0"),
                "informationUri": "https://github.com/pxawtyy/proofcms",
                "rules": list(rules.values()),
            }
        },
        "invocations": [
            {
                "executionSuccessful": True,
                "endTimeUtc": report.get("finished_at") or report.get("started_at"),
            }
        ],
        "results": results,
        "properties": {
            "run_id": report.get("run_id"),
            "summary_by_status": report.get("summary_by_status") or {},
        },
    }
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }
