from __future__ import annotations

from proofcms.modules.joomla import cve_2014_7984, cve_2020_13763, cve_2020_35616


def test_35616_version_gates():
    assert cve_2020_35616.classify_version("1.6.5") == "NOT_AFFECTED"
    assert cve_2020_35616.classify_version("1.7.0") == "LIKELY_VULNERABLE"
    assert cve_2020_35616.classify_version("3.9.22") == "LIKELY_VULNERABLE"
    assert cve_2020_35616.classify_version("3.9.23") == "PATCHED"
    assert cve_2020_35616.classify_version("5.0.0") == "PATCHED"
    assert cve_2020_35616.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_7984_version_gates():
    assert cve_2014_7984.classify_version("1.7.3") == "NOT_AFFECTED"
    assert cve_2014_7984.classify_version("2.5.18") == "LIKELY_VULNERABLE"
    assert cve_2014_7984.classify_version("2.5.19") == "PATCHED"
    assert cve_2014_7984.classify_version("3.0.0") == "LIKELY_VULNERABLE"
    assert cve_2014_7984.classify_version("3.2.2") == "LIKELY_VULNERABLE"
    assert cve_2014_7984.classify_version("3.2.3") == "PATCHED"
    assert cve_2014_7984.classify_version("4.0.0") == "PATCHED"
    assert cve_2014_7984.classify_version(None) == "INCONCLUSIVE"


def test_passive_core_check_has_no_active_proof():
    result = cve_2014_7984.check(
        "https://fixture.test", joomla_version="3.2.2", run_exploit_check=True
    )
    assert result.status == "LIKELY_VULNERABLE"
    assert result.exploit_available is False
    assert result.exploit_ran is False
    assert "version-based assessment only" in result.detail


def test_35616_aggressive_requires_account_and_group():
    result = cve_2020_35616.check(
        "https://fixture.test",
        joomla_version="3.9.22",
        run_exploit_check=True,
        exploit_mode="aggressive",
    )
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence is not None
    assert "acl_group" in result.detail


def test_35616_rules_validation_differential():
    from unittest.mock import patch

    token = "0123456789abcdef0123456789abcdef"
    form = {"status": 200, "body": f'<input name="{token}" value="1"><input name="jform[title]" value="x">'}
    affected = {
        "status": 200,
        "body": '<div class="alert-message">Invalid field: JFIELD_RULES_LABEL</div>',
    }
    fixed = {"status": 200, "body": '<div class="alert-message">Article saved.</div>'}
    args = {
        "admin_user": "lowuser",
        "admin_password": "pw",
        "acl_group": "20",
        "article_id": "1",
    }
    with patch.object(cve_2020_35616, "joomla_admin_login", return_value=True), patch.object(
        cve_2020_35616.HttpClient, "get", return_value=form
    ), patch.object(cve_2020_35616.HttpClient, "post", return_value=affected):
        result = cve_2020_35616.run_aggressive_probe("https://fixture.test", aggressive_args=args)
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["rules_validation_error"] is True

    with patch.object(cve_2020_35616, "joomla_admin_login", return_value=True), patch.object(
        cve_2020_35616.HttpClient, "get", return_value=form
    ), patch.object(cve_2020_35616.HttpClient, "post", return_value=fixed):
        result = cve_2020_35616.run_aggressive_probe("https://fixture.test", aggressive_args=args)
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["rules_validation_error"] is False


def test_13763_version_gates():
    assert cve_2020_13763.classify_version("2.4.0") == "NOT_AFFECTED"
    assert cve_2020_13763.classify_version("2.5.0") == "LIKELY_VULNERABLE"
    assert cve_2020_13763.classify_version("3.9.18") == "LIKELY_VULNERABLE"
    assert cve_2020_13763.classify_version("3.9.19") == "PATCHED"
    assert cve_2020_13763.classify_version("4.0.0") == "PATCHED"
    assert cve_2020_13763.classify_version(None) == "INCONCLUSIVE"


def test_13763_passive_check():
    result = cve_2020_13763.check(
        "https://fixture.test", joomla_version="3.9.18", run_exploit_check=True
    )
    assert result.status == "LIKELY_VULNERABLE"
    assert result.exploit_available is False
    assert result.exploit_ran is False
    assert "version-based assessment only" in result.detail


def test_metadata_types():
    assert cve_2020_35616.metadata()["vulnerability_type"] == "Improper Access Control"
    assert cve_2020_13763.metadata()["vulnerability_type"] == "Cross-Site Scripting (XSS)"
    assert cve_2014_7984.metadata()["vulnerability_type"] == "Authentication Bypass"
