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
    posted = {}

    def post(url, fields, timeout=12):
        posted.update(fields)
        return _response(final_url="http://target.test/index.php")

    client.post = post
    with (
        patch.object(registration_probe, "HttpClient", return_value=client),
        patch.object(registration_probe, "extract_csrf_from_html", return_value="a" * 32),
        patch.object(registration_probe, "rand_str", side_effect=["abcdefghij", "abcdefghijklmn", "missing1"]),
        patch.object(registration_probe, "_administrator_login", return_value={"verified": False}),
        patch.object(registration_probe, "_frontend_login", return_value=False),
    ):
        proof = registration_probe.submit_registration("http://target.test", group=7)

    assert proof["accepted"] is True
    assert posted["a" * 32] == "1"
    assert posted["user[groups][]"] == "7"
    assert posted["task"] == "user.register"


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
    assert result.confidence == "MEDIUM"
    assert submit.call_args.kwargs["group"] == 7
    assert "Administrator login was not verified" in result.detail
