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
    assert cve_2012_1563.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_11323_version_gates():
    assert cve_2018_11323.classify_version("2.4.0") == "NOT_AFFECTED"
    assert cve_2018_11323.classify_version("2.5.0") == "LIKELY_VULNERABLE"
    assert cve_2018_11323.classify_version("3.8.7") == "LIKELY_VULNERABLE"
    assert cve_2018_11323.classify_version("3.8.8") == "PATCHED"
    assert cve_2018_11323.classify_version("4.0.0") == "PATCHED"
    assert cve_2018_11323.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_1563_aggressive_requires_mode():
    result = cve_2012_1563.check(
        "https://fixture.test", joomla_version="2.5.2", run_exploit_check=True
    )
    assert result.status == "LIKELY_VULNERABLE"
    assert result.exploit_ran is False
    assert "isolated-lab aggressive" in result.detail


def test_1563_registration_state_differential():
    from unittest.mock import patch

    token = "0123456789abcdef0123456789abcdef"
    form_html = f'<input name="{token}" value="1"><input name="jform[username]" value="">'
    step1 = {"status": 200, "body": "The email address you entered is already in use or invalid."}
    affected = {
        "status": 200,
        "body": "Registration failed: Only users with Super Admin permissions can change other Super Admin user accounts.",
    }
    fixed = {"status": 200, "body": "Registration failed: An error was encountered while sending the registration email."}
    with patch.object(cve_2012_1563, "_token", return_value=token), patch.object(
        cve_2012_1563, "HttpClient"
    ) as client:
        instance = client.return_value
        instance.get.return_value = {"status": 200, "body": form_html}
        instance.post.side_effect = [step1, affected]
        result = cve_2012_1563.run_aggressive_probe("https://fixture.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["step2_super_message"] is True
    assert result.evidence["step1_invalid_email_message"] is True

    with patch.object(cve_2012_1563, "_token", return_value=token), patch.object(
        cve_2012_1563, "HttpClient"
    ) as client:
        instance = client.return_value
        instance.get.return_value = {"status": 200, "body": form_html}
        instance.post.side_effect = [step1, fixed]
        result = cve_2012_1563.run_aggressive_probe("https://fixture.test")
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["step2_super_message"] is False


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
