from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_56292, cve_2026_94132


def inventory(version: str, edition: str | None = None) -> dict:
    return {
        "acymailing": {
            "found": True,
            "version": version,
            "edition": edition,
            "source": "/administrator/components/com_acymailing/acymailing.xml",
        }
    }


def test_acymailing_581_matches_critical_sqli_range():
    result = cve_2026_56292.check("https://target.test", plugins=inventory("5.8.1"))
    assert result.status == "LIKELY_VULNERABLE"
    assert result.confidence == "HIGH"


def test_acymailing_enterprise_581_matches_mailbox_rce_range():
    result = cve_2026_94132.check("https://target.test", plugins=inventory("5.8.1", "enterprise"))
    assert result.status == "LIKELY_VULNERABLE"


def test_mailbox_rce_does_not_assume_enterprise_edition():
    result = cve_2026_94132.check("https://target.test", plugins=inventory("5.8.1"))
    assert result.status == "INCONCLUSIVE"


def test_acymailing_fixed_versions_are_patched():
    assert cve_2026_56292.check("https://target.test", plugins=inventory("10.11.1")).status == "PATCHED"
    assert cve_2026_94132.check(
        "https://target.test", plugins=inventory("11.1.0", "enterprise")
    ).status == "PATCHED"


def test_sqli_safe_probe_confirms_only_constant_json_differential():
    marker = "proofcms_abcdefghijkl"

    class Client:
        def __init__(self, *args, **kwargs):
            pass

        def get(self, url, timeout=12):
            if "UNION" in url:
                return {
                    "status": 200,
                    "body": '{"data":{"elements":[{"id":"' + marker + '"}]}}',
                    "redirected": False,
                }
            return {"status": 200, "body": '{"data":{"elements":[{"id":"1"}]}}', "redirected": False}

    with (
        patch.object(cve_2026_56292, "HttpClient", Client),
        patch.object(cve_2026_56292, "rand_str", return_value="abcdefghijkl"),
    ):
        proof = cve_2026_56292.run_safe_probe("https://target.test")
    assert proof["confirmed"] is True


def test_sqli_check_promotes_confirmed_safe_proof():
    with patch.object(
        cve_2026_56292,
        "run_safe_probe",
        return_value={"confirmed": True, "blocked": False, "proof_url": "/proof", "attempts": []},
    ):
        result = cve_2026_56292.check(
            "https://target.test",
            plugins=inventory("10.11.0"),
            run_exploit_check=True,
            exploit_mode="safe",
        )
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"


def test_mailbox_safe_probe_never_claims_rce():
    with patch.object(
        cve_2026_94132,
        "run_safe_probe",
        return_value={
            "upload_path": "/media/com_acym/upload/",
            "directory_status": 200,
            "missing_control_status": 404,
            "directory_listing": True,
            "distinct_from_missing_control": True,
        },
    ):
        result = cve_2026_94132.check(
            "https://target.test",
            plugins=inventory("5.8.1", "enterprise"),
            run_exploit_check=True,
            exploit_mode="safe",
        )
    assert result.status == "LIKELY_VULNERABLE"
    assert result.exploit_ran is True
    assert "RCE is not claimed" in result.detail
