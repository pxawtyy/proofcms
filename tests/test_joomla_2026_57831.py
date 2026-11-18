from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_57831


def test_dpcalendar_57831_version_boundaries():
    assert cve_2026_57831.classify_version("8.17.0") == "NOT_AFFECTED"
    assert cve_2026_57831.classify_version("8.18.0") == "LIKELY_VULNERABLE"
    assert cve_2026_57831.classify_version("10.10.0") == "LIKELY_VULNERABLE"
    assert cve_2026_57831.classify_version("10.11.1") == "LIKELY_VULNERABLE"
    assert cve_2026_57831.classify_version("10.11.2") == "NOT_AFFECTED"
    assert cve_2026_57831.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_dpcalendar_57831_delay_confirms():
    responses = [({"status": 200}, 0.30), ({"status": 200}, 3.10)]
    with patch.object(cve_2026_57831, "HttpClient", return_value=object()), patch.object(
        cve_2026_57831, "_timed_get", side_effect=responses
    ):
        result = cve_2026_57831.run_aggressive_probe("https://target.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["delayed"] is True
    assert result.evidence["delta_seconds"] >= 1.2


def test_dpcalendar_57831_patched_has_no_delay():
    responses = [({"status": 200}, 0.15), ({"status": 200}, 0.16)]
    with patch.object(cve_2026_57831, "HttpClient", return_value=object()), patch.object(
        cve_2026_57831, "_timed_get", side_effect=responses
    ):
        result = cve_2026_57831.run_aggressive_probe("https://target.test")
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["delayed"] is False


def test_dpcalendar_57831_passive_reports_vulnerable_version():
    result = cve_2026_57831.passive_result({"dpcalendar": {"found": True, "version": "10.10.0"}})
    assert result.status == "LIKELY_VULNERABLE"


def test_dpcalendar_57831_passive_ignores_absent_component():
    result = cve_2026_57831.passive_result({"dpcalendar": {"found": False}})
    assert result.status == "NOT_DETECTED"
