from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_94130


class _DummyClient:
    def __init__(self, *args, **kwargs) -> None:
        pass

    def get(self, url: str, timeout=None):
        return {"status": 200, "body": ""}


def test_youtubegallery_94130_version_boundaries():
    assert cve_2026_94130.classify_version("5.7.1") == "LIKELY_VULNERABLE"
    assert cve_2026_94130.classify_version("5.7.2") == "LIKELY_VULNERABLE"
    assert cve_2026_94130.classify_version("5.7.3") == "NOT_AFFECTED"
    assert cve_2026_94130.classify_version("5.7.4") == "NOT_AFFECTED"
    assert cve_2026_94130.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_youtubegallery_94130_sleep_confirms():
    responses = [({"status": 200, "body": "[]"}, 0.20), ({"status": 200, "body": "[]"}, 4.20)]
    with patch.object(cve_2026_94130, "HttpClient", return_value=_DummyClient()), patch.object(
        cve_2026_94130, "_timed_get", side_effect=responses
    ):
        result = cve_2026_94130.run_aggressive_probe("https://target.test", list_id=1, theme_id=1)
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["delta_seconds"] >= cve_2026_94130.SLEEP_THRESHOLD


def test_youtubegallery_94130_patched_is_not_confirmed():
    responses = [({"status": 200, "body": "[]"}, 0.20), ({"status": 200, "body": "[]"}, 0.30)]
    with patch.object(cve_2026_94130, "HttpClient", return_value=_DummyClient()), patch.object(
        cve_2026_94130, "_timed_get", side_effect=responses
    ):
        result = cve_2026_94130.run_aggressive_probe("https://target.test", list_id=1, theme_id=1)
    assert result.status == "NOT_CONFIRMED"


def test_youtubegallery_94130_missing_gallery_is_blocked():
    responses = [({"status": 404, "body": ""}, 0.10), ({"status": 404, "body": ""}, 0.10)]
    with patch.object(cve_2026_94130, "HttpClient", return_value=_DummyClient()), patch.object(
        cve_2026_94130, "_timed_get", side_effect=responses
    ):
        result = cve_2026_94130.run_aggressive_probe("https://target.test", list_id=99, theme_id=99)
    assert result.status == "BLOCKED_EXTERNAL"


def test_youtubegallery_94130_passive_reports_vulnerable_version():
    result = cve_2026_94130.passive_result({"youtubegallery": {"found": True, "version": "5.7.2"}})
    assert result.status == "LIKELY_VULNERABLE"


def test_youtubegallery_94130_passive_ignores_absent_component():
    result = cve_2026_94130.passive_result({"youtubegallery": {"found": False}})
    assert result.status == "NOT_DETECTED"
