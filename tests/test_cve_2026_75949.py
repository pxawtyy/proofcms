from __future__ import annotations

from proofcms.modules.joomla import cve_2026_75949


def test_version_classification() -> None:
    assert cve_2026_75949.classify_version("6.2.0") == "LIKELY_VULNERABLE"
    assert cve_2026_75949.classify_version("6.2.2") == "LIKELY_VULNERABLE"
    assert cve_2026_75949.classify_version("6.2.3") == "NOT_AFFECTED"
    assert cve_2026_75949.classify_version("6.2.4") == "NOT_AFFECTED"
    assert cve_2026_75949.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_passive_result_vulnerable() -> None:
    finding = cve_2026_75949.passive_result(
        {"jbusinessdirectory": {"found": True, "version": "6.2.1"}}
    )
    assert finding.status == "LIKELY_VULNERABLE"
    assert finding.component_version == "6.2.1"


def test_passive_result_not_detected() -> None:
    finding = cve_2026_75949.passive_result({})
    assert finding.status == "NOT_DETECTED"


def test_xml_value() -> None:
    body = '<uploads><picture name="marker.txt" error="0" info="/tmp/marker.txt" /></uploads>'
    assert cve_2026_75949._xml_value(body, "name") == "marker.txt"
    assert cve_2026_75949._xml_value(body, "error") == "0"
    assert cve_2026_75949._xml_value(body, "missing") is None


def test_metadata() -> None:
    meta = cve_2026_75949.metadata()
    assert meta["cve"] == "CVE-2026-75949"
    assert meta["exploit_modes"] == ["safe", "aggressive"]
    assert meta["required_detectors"] == ["jbusinessdirectory"]
