from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_57832


def test_edocman_57832_version_boundaries():
    assert cve_2026_57832.classify_version("3.2") == "LIKELY_VULNERABLE"
    assert cve_2026_57832.classify_version("3.8.9") == "LIKELY_VULNERABLE"
    assert cve_2026_57832.classify_version("3.9") == "NOT_AFFECTED"
    assert cve_2026_57832.classify_version("3.10") == "NOT_AFFECTED"
    assert cve_2026_57832.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_edocman_57832_delay_confirms():
    responses = [({"status": 200}, 0.25), ({"status": 200}, 3.30)]
    with patch.object(cve_2026_57832, "HttpClient", return_value=object()), patch.object(
        cve_2026_57832, "_timed_get", side_effect=responses
    ):
        result = cve_2026_57832.run_aggressive_probe("https://target.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["delayed"] is True
    assert result.evidence["delta_seconds"] >= 1.2


def test_edocman_57832_patched_has_no_delay():
    responses = [({"status": 303}, 0.10), ({"status": 303}, 0.08)]
    with patch.object(cve_2026_57832, "HttpClient", return_value=object()), patch.object(
        cve_2026_57832, "_timed_get", side_effect=responses
    ):
        result = cve_2026_57832.run_aggressive_probe("https://target.test")
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["delayed"] is False


def test_edocman_57832_passive_reports_vulnerable_version():
    result = cve_2026_57832.passive_result({"edocman": {"found": True, "version": "3.2"}})
    assert result.status == "LIKELY_VULNERABLE"


def test_edocman_57832_passive_ignores_absent_component():
    result = cve_2026_57832.passive_result({"edocman": {"found": False}})
    assert result.status == "NOT_DETECTED"


def test_edocman_57832_aggressive_uses_seed_email():
    responses = [({"status": 200}, 0.20), ({"status": 200}, 3.20)]
    with patch.object(cve_2026_57832, "HttpClient", return_value=object()), patch.object(
        cve_2026_57832, "_timed_get", side_effect=responses
    ) as timed:
        result = cve_2026_57832.check(
            "https://target.test",
            run_exploit_check=True,
            exploit_mode="aggressive",
            aggressive_args={"email": "seed@example.test", "delay": "3"},
            plugins={"edocman": {"found": True, "version": "3.2"}},
        )
    assert result.status == "VULNERABLE"
    assert "seed%40example.test" in timed.call_args_list[0].args[1]
