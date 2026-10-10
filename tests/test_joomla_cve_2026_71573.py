from __future__ import annotations

from unittest.mock import patch

import pytest

from proofcms.modules.joomla import cve_2026_71573


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("3.10.12", "NOT_AFFECTED"),
        ("4.0.0", "LIKELY_VULNERABLE"),
        ("5.4.7", "LIKELY_VULNERABLE"),
        ("5.4.8", "PATCHED"),
        ("6.0.0", "LIKELY_VULNERABLE"),
        ("6.1.2", "LIKELY_VULNERABLE"),
        ("6.1.3", "PATCHED"),
    ],
)
def test_cors_advisory_version_boundaries(version, expected):
    assert cve_2026_71573.classify_version(version) == expected


def test_cors_probe_confirms_unique_origin_reflection():
    def response(request_url, **kwargs):
        origin = kwargs["headers"]["Origin"]
        assert origin.startswith("https://proofcms-") and origin.endswith(".invalid")
        assert kwargs["method"] == "OPTIONS"
        assert kwargs["follow_redirects"] is False
        return {
            "status": 204,
            "headers": {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            },
        }

    with patch("proofcms.modules.joomla.cve_2026_71573.HttpClient.request", side_effect=response):
        result = cve_2026_71573.check(
            "https://fixture.test",
            joomla_version="5.4.7",
            run_exploit_check=True,
        )
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.exploit_ran is True
    assert result.vulnerability_type == "Improper CORS Validation"


def test_cors_probe_does_not_treat_wildcard_as_cve_confirmation():
    response = {"status": 204, "headers": {"Access-Control-Allow-Origin": "*"}}
    with patch("proofcms.modules.joomla.cve_2026_71573.HttpClient.request", return_value=response):
        result = cve_2026_71573.check(
            "https://fixture.test",
            joomla_version="5.4.7",
            run_exploit_check=True,
        )
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["access_control_allow_origin"] == "*"


def test_cors_probe_is_skipped_for_patched_version():
    with patch("proofcms.modules.joomla.cve_2026_71573.HttpClient.request") as request:
        result = cve_2026_71573.check(
            "https://fixture.test",
            joomla_version="5.4.8",
            run_exploit_check=True,
        )
    request.assert_not_called()
    assert result.status == "PATCHED"
