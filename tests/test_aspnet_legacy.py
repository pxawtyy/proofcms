from unittest.mock import patch

from proofcms.modules.generic import cve_2010_3332, cve_2011_3416

RUNTIME = {
    "detected": True,
    "version": "2.0.50727",
    "source": "/:X-AspNet-Version",
    "server": None,
}


def test_2010_3332_netfx2_is_likely_vulnerable():
    result = cve_2010_3332.check("https://fixture.test", aspnet_runtime=RUNTIME)
    assert result.status == "LIKELY_VULNERABLE"
    assert result.confidence == "HIGH"
    assert "MS10-070" in result.detail


def test_2010_3332_safe_probe_confirms_status_differential():
    page = {"status": 200, "body": 'ScriptResource.axd?d=AAAA', "body_hash": "page"}
    control = {"status": 200, "body": "ok", "body_hash": "control"}
    probe = {"status": 500, "body": "error", "body_hash": "probe"}
    with patch.object(cve_2010_3332, "HttpClient") as client:
        client.return_value.get.side_effect = [page, control, probe]
        result = cve_2010_3332.check(
            "https://fixture.test",
            run_exploit_check=True,
            exploit_mode="safe",
            aspnet_runtime=RUNTIME,
            timeout=1,
        )
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["probe_status"] == 500


def test_2010_3332_no_token_keeps_version_finding():
    page = {"status": 200, "body": "<html>no resource</html>", "body_hash": "page"}
    with patch.object(cve_2010_3332, "HttpClient") as client:
        client.return_value.get.return_value = page
        result = cve_2010_3332.check(
            "https://fixture.test",
            run_exploit_check=True,
            exploit_mode="safe",
            aspnet_runtime=RUNTIME,
            timeout=1,
        )
    assert result.status == "LIKELY_VULNERABLE"
    assert result.confidence == "HIGH"
    assert "could not be exercised" in result.detail


def test_2011_3416_netfx2_is_likely_vulnerable():
    result = cve_2011_3416.check("https://fixture.test", aspnet_runtime=RUNTIME)
    assert result.status == "LIKELY_VULNERABLE"
    assert result.confidence == "HIGH"
    assert "MS11-100" in result.detail


def test_2011_3416_is_passive():
    result = cve_2011_3416.check(
        "https://fixture.test",
        run_exploit_check=True,
        aspnet_runtime=RUNTIME,
    )
    assert result.exploit_ran is False
    assert "passive-only" in result.detail
