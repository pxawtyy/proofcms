from __future__ import annotations

from proofcms.modules.joomla import cve_2026_81566


def test_version_classification() -> None:
    assert cve_2026_81566.classify_version("6.0.0") == "LIKELY_VULNERABLE"
    assert cve_2026_81566.classify_version("6.9.9") == "LIKELY_VULNERABLE"
    assert cve_2026_81566.classify_version("6.10.0") == "NOT_AFFECTED"
    assert cve_2026_81566.classify_version("5.9.0") == "NOT_AFFECTED"
    assert cve_2026_81566.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_passive_result_vulnerable() -> None:
    finding = cve_2026_81566.passive_result(
        {"sppagebuilder": {"found": True, "version": "6.0.0"}}
    )
    assert finding.status == "LIKELY_VULNERABLE"
    assert finding.component_version == "6.0.0"


def test_passive_result_not_detected() -> None:
    finding = cve_2026_81566.passive_result({})
    assert finding.status == "NOT_DETECTED"


def test_metadata() -> None:
    meta = cve_2026_81566.metadata()
    assert meta["cve"] == "CVE-2026-81566"
    assert meta["exploit_modes"] == ["safe", "aggressive"]
    assert meta["required_detectors"] == ["sppagebuilder"]
