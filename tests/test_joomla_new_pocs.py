from unittest.mock import patch

from proofcms.modules.joomla import cve_2015_7857, cve_2016_8869, cve_2016_8870, registration_probe


def _response(status=200, body="", body_hash="hash", redirected=False, final_url="http://target.test/"):
    return {
        "status": status,
        "body": body,
        "body_hash": body_hash,
        "redirected": redirected,
        "final_url": final_url,
    }


def test_cve_2015_7857_confirms_only_unique_sql_error():
    client = type("Client", (), {})()
    client.get = lambda url, timeout=12: (
        _response(body="normal history", body_hash="control")
        if "list%5Bselect%5D=1%2C" not in url
        else _response(body="Unknown column 'proofcms_missing_column'", body_hash="probe")
    )
    with patch.object(cve_2015_7857, "HttpClient", return_value=client):
        result = cve_2015_7857.check(
            "http://target.test",
            "3.4.4",
            run_exploit_check=True,
            exploit_mode="safe",
        )

    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.exploit_ran is True


def test_cve_2015_7857_rejects_fake_200_without_differential():
    client = type("Client", (), {})()
    client.get = lambda url, timeout=12: _response(body="homepage", body_hash="same")
    with patch.object(cve_2015_7857, "HttpClient", return_value=client):
        result = cve_2015_7857.check(
            "http://target.test",
            "3.4.4",
            run_exploit_check=True,
            exploit_mode="safe",
        )

    assert result.status == "NOT_CONFIRMED"


def test_registration_probe_uses_session_token_and_optional_group():
    client = type("Client", (), {})()
    client.get = lambda url, timeout=12: _response(body='<input name="a" value="1">')
    posts = []

    def post(url, fields, timeout=12):
        posts.append(dict(fields))
        if len(posts) == 2:
            return _response(
                body=(
                    "The username you entered is invalid or already in use. "
                    "The email address you entered is already in use or invalid."
                )
            )
        return _response(final_url="http://target.test/index.php")

    client.post = post
    with (
        patch.object(registration_probe, "HttpClient", return_value=client),
        patch.object(registration_probe, "extract_csrf_from_html", return_value="a" * 32),
        patch.object(registration_probe, "rand_str", side_effect=["abcdefghij", "abcdefghijklmn"]),
    ):
        proof = registration_probe.submit_registration("http://target.test", group=7)

    posted = posts[0]
    assert proof["accepted"] is True
    assert proof["account_created"] is True
    assert posted["a" * 32] == "1"
    assert posted["groups[]"] == "7"
    assert "user[groups][]" not in posted
    assert posted["task"] == "registration.register"
    assert len(posts) == 2


def test_registration_cves_require_aggressive_mode():
    for module in (cve_2016_8869, cve_2016_8870):
        result = module.check(
            "http://target.test",
            "3.6.3",
            run_exploit_check=True,
            exploit_mode="safe",
        )
        assert result.status == "LIKELY_VULNERABLE"
        assert result.exploit_ran is False


def test_privilege_probe_reports_sent_without_claiming_confirmation():
    proof = {
        "sent": True,
        "accepted": True,
        "status": 200,
        "proof_url": "http://target.test/index.php?option=com_users&task=user.register",
        "username": "proofcms_test",
        "password": "Pc!test",
        "email": "proofcms_test@example.invalid",
    }
    with patch.object(cve_2016_8869, "submit_registration", return_value=proof) as submit:
        result = cve_2016_8869.check(
            "http://target.test",
            "3.6.3",
            run_exploit_check=True,
            exploit_mode="aggressive",
        )

    assert result.status == "AGGRESSIVE_SENT"
    assert result.confidence == "LOW"
    assert submit.call_args.kwargs["group"] == 7
    assert "collision oracle did not confirm" in result.detail


def test_registration_cves_use_collision_oracle_semantics():
    proof = {
        "sent": True,
        "accepted": True,
        "account_created": True,
        "status": 200,
        "proof_url": "http://target.test/index.php?option=com_users&view=registration",
        "username": "proofcms_test",
        "password": "Pc!test",
        "email": "proofcms_test@example.invalid",
        "registration_task": "registration.register",
        "group_field": "groups[]",
        "collision_markers": ["username_exists", "email_exists"],
    }
    with patch.object(cve_2016_8870, "submit_registration", return_value=proof):
        account = cve_2016_8870.check(
            "http://target.test", "3.6.3", run_exploit_check=True, exploit_mode="aggressive"
        )
    with patch.object(cve_2016_8869, "submit_registration", return_value=proof):
        privilege = cve_2016_8869.check(
            "http://target.test", "3.6.3", run_exploit_check=True, exploit_mode="aggressive"
        )

    assert account.status == "VULNERABLE"
    assert account.confidence == "CONFIRMED"
    assert privilege.status == "LIKELY_VULNERABLE"
    assert privilege.confidence == "HIGH"
    assert privilege.evidence["privilege_confirmed"] is False
