from __future__ import annotations

from proofcms.cli import apply_waf_classification
from proofcms.core.models import Finding
from proofcms.reporting.diff import build_scan_diff, format_scan_diff
from proofcms.reporting.sarif import build_sarif_report


def _finding(cve: str, status: str, version: str | None = None, detail: str = "") -> dict:
    return {
        "cve": cve,
        "name": f"{cve} name",
        "status": status,
        "confidence": "HIGH",
        "component": "Example",
        "component_version": version,
        "affected_rule": "<=1.0",
        "vulnerability_type": "SQL Injection",
        "exploit_available": True,
        "exploit_ran": status in {"VULNERABLE", "VULNERABLE_UPLOAD_ONLY"},
        "detail": detail or status,
    }


def _report(targets: list[dict]) -> dict:
    return {
        "tool": "ProofCMS",
        "tool_version": "2.1.0",
        "run_id": "run-1",
        "finished_at": "2026-11-21T00:00:00+00:00",
        "summary_by_status": {},
        "targets": targets,
    }


def test_waf_classification_turns_negative_into_blocked_external():
    result = Finding(
        cve="CVE-2026-0001",
        name="Example",
        status="NOT_CONFIRMED",
        confidence="MEDIUM",
        detail="The probe did not confirm the issue.",
    )
    classified = apply_waf_classification(
        result,
        [{"status": 403, "waf": "cloudflare"}],
        run_exploit_check=True,
    )
    assert classified.status == "BLOCKED_EXTERNAL"
    assert classified.evidence["waf"] == "cloudflare"
    assert classified.evidence["waf_responses"] == 1
    assert "cloudflare" in classified.detail


def test_waf_classification_never_overrides_confirmed_findings():
    result = Finding(
        cve="CVE-2026-0001",
        name="Example",
        status="VULNERABLE",
        confidence="CONFIRMED",
        detail="confirmed",
    )
    classified = apply_waf_classification(result, [{"waf": "cloudflare"}], run_exploit_check=True)
    assert classified.status == "VULNERABLE"
    assert classified.evidence is None


def test_waf_classification_is_inert_without_an_active_probe():
    result = Finding(
        cve="CVE-2026-0001",
        name="Example",
        status="NOT_CONFIRMED",
        confidence="MEDIUM",
        detail="negative",
    )
    classified = apply_waf_classification(result, [{"waf": "cloudflare"}], run_exploit_check=False)
    assert classified.status == "NOT_CONFIRMED"


def test_scan_diff_reports_status_version_new_and_removed():
    previous = _report(
        [
            {
                "target": "https://target.test",
                "scan_base_url": "https://target.test",
                "results": [
                    _finding("CVE-A", "VULNERABLE", "1.0.0"),
                    _finding("CVE-B", "VULNERABLE", "2.0.0"),
                    _finding("CVE-C", "VULNERABLE", "3.0.0"),
                ],
            }
        ]
    )
    current = _report(
        [
            {
                "target": "https://target.test",
                "scan_base_url": "https://target.test",
                "results": [
                    _finding("CVE-A", "PATCHED", "1.0.0"),
                    _finding("CVE-B", "VULNERABLE", "2.1.0"),
                    _finding("CVE-D", "LIKELY_VULNERABLE", "4.0.0"),
                ],
            }
        ]
    )
    diff = build_scan_diff(previous, current, "previous.json")
    assert diff["summary"] == {
        "new": 1,
        "removed": 1,
        "status_changed": 1,
        "version_changed": 1,
    }
    kinds = {change["cve"]: change["change"] for change in diff["changes"]}
    assert kinds == {
        "CVE-A": "status_changed",
        "CVE-B": "version_changed",
        "CVE-C": "removed",
        "CVE-D": "new",
    }
    text = format_scan_diff(diff)
    assert "VULNERABLE -> PATCHED" in text
    assert "NEW" in text
    assert "REMOVED" in text


def test_sarif_report_maps_findings_to_rules_and_levels():
    report = _report(
        [
            {
                "target": "https://target.test",
                "scan_base_url": "https://target.test",
                "results": [
                    _finding("CVE-A", "VULNERABLE", "1.0.0"),
                    _finding("CVE-B", "PATCHED", "2.0.0"),
                ],
            }
        ]
    )
    sarif = build_sarif_report(report)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "ProofCMS"
    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    assert set(rules) == {"CVE-A", "CVE-B"}
    results = {result["ruleId"]: result for result in run["results"]}
    assert results["CVE-A"]["kind"] == "fail"
    assert results["CVE-A"]["level"] == "error"
    assert results["CVE-B"]["kind"] == "pass"
    assert results["CVE-B"]["level"] == "note"
    assert results["CVE-A"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "https://target.test"
    )
