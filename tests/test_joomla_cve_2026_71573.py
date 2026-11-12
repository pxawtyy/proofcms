from __future__ import annotations

from unittest.mock import patch

import pytest

from proofcms.modules.joomla import cve_2026_71573

TOKEN = "lab-api-token"


class FakeClient:
    def __init__(self, state):
        self.state = state

    def request(self, url, **kwargs):
        method = kwargs.get("method")
        origin = kwargs["headers"]["Origin"]
        assert origin.startswith("https://proofcms-") and origin.endswith(".invalid")
        assert kwargs["follow_redirects"] is False
        if method == "OPTIONS":
            if self.state.get("vulnerable"):
                return {"status": 204, "headers": {"Access-Control-Allow-Origin": "https://trusted.example.test"}}
            return {"status": 403, "headers": {}}
        if method == "GET":
            if self.state.get("vulnerable"):
                return {
                    "status": 200,
                    "headers": {
                        "Access-Control-Allow-Origin": origin,
                        "Access-Control-Allow-Credentials": "true",
                    },
                }
            return {"status": 200, "headers": {}}
        raise AssertionError(f"unexpected method {method}")


def _run(state, token=TOKEN):
    with patch.object(cve_2026_71573, "HttpClient", side_effect=lambda *a, **k: FakeClient(state)):
        return cve_2026_71573.check(
            "https://fixture.test",
            joomla_version="5.4.7",
            run_exploit_check=True,
            aggressive_args={"api_token": token} if token else None,
        )


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


def test_cors_probe_confirms_origin_reflection_with_credentials():
    result = _run({"vulnerable": True})
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.exploit_ran is True
    assert result.vulnerability_type == "Improper CORS Validation"
    assert result.evidence["access_control_allow_credentials"] == "true"


def test_cors_probe_without_token_does_not_confirm():
    result = _run({"vulnerable": True}, token=None)
    assert result.status == "NOT_CONFIRMED"
    assert "api_token" in result.detail


def test_cors_probe_does_not_confirm_patched_behavior():
    result = _run({"vulnerable": False})
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["preflight_status"] == 403
    assert result.evidence["access_control_allow_origin"] is None


def test_cors_probe_does_not_treat_wildcard_as_confirmation():
    class WildcardClient(FakeClient):
        def request(self, url, **kwargs):
            if kwargs.get("method") == "GET":
                return {"status": 200, "headers": {"Access-Control-Allow-Origin": "*"}}
            return {"status": 204, "headers": {"Access-Control-Allow-Origin": "*"}}

    with patch.object(cve_2026_71573, "HttpClient", side_effect=lambda *a, **k: WildcardClient({})):
        result = cve_2026_71573.check(
            "https://fixture.test",
            joomla_version="5.4.7",
            run_exploit_check=True,
            aggressive_args={"api_token": TOKEN},
        )
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["access_control_allow_origin"] == "*"


def test_cors_probe_is_skipped_for_patched_version():
    with patch.object(cve_2026_71573, "HttpClient") as client:
        result = cve_2026_71573.check(
            "https://fixture.test",
            joomla_version="5.4.8",
            run_exploit_check=True,
            aggressive_args={"api_token": TOKEN},
        )
    client.assert_not_called()
    assert result.status == "PATCHED"
