from __future__ import annotations

from proofcms.modules.joomla import cve_2012_1563, cve_2018_11323


def test_1563_version_gates():
    assert cve_2012_1563.classify_version("1.5.2") == "NOT_AFFECTED"
    assert cve_2012_1563.classify_version("1.6.0") == "LIKELY_VULNERABLE"
    assert cve_2012_1563.classify_version("1.7.5") == "LIKELY_VULNERABLE"
    assert cve_2012_1563.classify_version("2.4.0") == "NOT_AFFECTED"
    assert cve_2012_1563.classify_version("2.5.0") == "LIKELY_VULNERABLE"
    assert cve_2012_1563.classify_version("2.5.2") == "LIKELY_VULNERABLE"
    assert cve_2012_1563.classify_version("2.5.3") == "PATCHED"
    assert cve_2012_1563.classify_version("3.0.0") == "PATCHED"
    assert cve_2012_1563.classify_version(None) == "INCONCLUSIVE"


def test_11323_version_gates():
    assert cve_2018_11323.classify_version("2.4.0") == "NOT_AFFECTED"
    assert cve_2018_11323.classify_version("2.5.0") == "LIKELY_VULNERABLE"
    assert cve_2018_11323.classify_version("3.8.7") == "LIKELY_VULNERABLE"
    assert cve_2018_11323.classify_version("3.8.8") == "PATCHED"
    assert cve_2018_11323.classify_version("4.0.0") == "PATCHED"
    assert cve_2018_11323.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_passive_core_check_has_no_active_proof():
    result = cve_2012_1563.check(
        "https://fixture.test", joomla_version="2.5.2", run_exploit_check=True
    )
    assert result.status == "LIKELY_VULNERABLE"
    assert result.exploit_available is False
    assert result.exploit_ran is False
    assert "version-based assessment only" in result.detail


def test_11323_safe_probe_requires_account_and_level():
    result = cve_2018_11323.check(
        "https://fixture.test",
        joomla_version="3.8.7",
        run_exploit_check=True,
    )
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence is not None
    assert "viewlevel_id" in result.detail
    assert result.exploit_ran is False


def test_11323_access_level_differential():
    from unittest.mock import patch

    baseline = {
        "status": 200,
        "body": "<title>Users: Edit Viewing Access Level - Lab</title>",
    }
    affected = {
        "status": 200,
        "body": "<title>Users: Edit Viewing Access Level - Lab</title>",
    }
    fixed = {
        "status": 200,
        "body": '<div class="alert-message">Edit not permitted.</div>',
    }
    args = {
        "admin_user": "lowuser",
        "admin_password": "pw",
        "viewlevel_id": "100",
    }
    with patch.object(cve_2018_11323, "joomla_admin_login", return_value=True), patch.object(
        cve_2018_11323.HttpClient, "get", side_effect=[baseline, affected]
    ):
        result = cve_2018_11323.run_safe_probe("https://fixture.test", aggressive_args=args)
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["target_form_opened"] is True
    assert result.evidence["baseline_form_opened"] is True

    with patch.object(cve_2018_11323, "joomla_admin_login", return_value=True), patch.object(
        cve_2018_11323.HttpClient, "get", side_effect=[baseline, fixed]
    ):
        result = cve_2018_11323.run_safe_probe("https://fixture.test", aggressive_args=args)
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["target_denied"] is True


def test_metadata_types():
    assert cve_2012_1563.metadata()["vulnerability_type"] == "Privilege Escalation"
    assert cve_2018_11323.metadata()["vulnerability_type"] == "Improper Access Control"
