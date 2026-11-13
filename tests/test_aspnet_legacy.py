from unittest.mock import patch

from proofcms.modules.generic import cve_2010_3332, cve_2011_3416

RUNTIME = {
    "detected": True,
    "version": "2.0.50727",
    "source": "/login.aspx:X-AspNet-Version",
    "server": None,
}


def test_2010_3332_without_webforms_surface_is_inconclusive():
    page = {"status": 200, "body": "<html>no resource</html>", "body_hash": "page"}
    with patch.object(cve_2010_3332, "HttpClient") as client:
        client.return_value.get.return_value = page
        result = cve_2010_3332.check("https://fixture.test", aspnet_runtime=RUNTIME, timeout=1)
    assert result.status == "INCONCLUSIVE"
    assert result.confidence == "HIGH"
    assert "oracle surface is absent" in result.detail
    assert "/login.aspx:X-AspNet-Version" in result.detail


def test_2010_3332_viewstate_surface_is_likely_vulnerable():
    page = {
        "status": 200,
        "body": '<input type="hidden" name="__VIEWSTATE" value="x">',
        "body_hash": "page",
    }
    with patch.object(cve_2010_3332, "HttpClient") as client:
        client.return_value.get.return_value = page
        result = cve_2010_3332.check("https://fixture.test", aspnet_runtime=RUNTIME, timeout=1)
    assert result.status == "LIKELY_VULNERABLE"
    assert result.confidence == "HIGH"
    assert result.evidence["viewstate"] is True


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


def test_2010_3332_surface_without_token_is_likely():
    page = {"status": 200, "body": '<input name="__VIEWSTATE">', "body_hash": "page"}
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
    assert result.exploit_ran is True
    assert "no ScriptResource/WebResource token" in result.detail


def test_2011_3416_forms_auth_surface_is_likely_vulnerable():
    page = {
        "status": 200,
        "headers": {"Set-Cookie": ".ASPXAUTH=abc; path=/; HttpOnly"},
        "body": "<form></form>",
    }
    with patch.object(cve_2011_3416, "HttpClient") as client:
        client.return_value.get.return_value = page
        result = cve_2011_3416.check("https://fixture.test", aspnet_runtime=RUNTIME, timeout=1)
    assert result.status == "LIKELY_VULNERABLE"
    assert result.confidence == "HIGH"
    assert result.evidence["aspnet_auth_cookie"] is True


def test_2011_3416_genexus_sso_is_not_affected():
    page = {
        "status": 200,
        "headers": {"Set-Cookie": "GX_SESSION_ID=abc; path=/"},
        "body": "<script src='gxcfg.js'></script><input name='GXState'>",
    }
    with patch.object(cve_2011_3416, "HttpClient") as client:
        client.return_value.get.return_value = page
        result = cve_2011_3416.check("https://fixture.test", aspnet_runtime=RUNTIME, timeout=1)
    assert result.status == "NOT_AFFECTED"
    assert result.confidence == "HIGH"
    assert "GeneXus SSO" in result.detail


def test_2011_3416_is_passive():
    page = {
        "status": 200,
        "headers": {"Set-Cookie": ".ASPXAUTH=abc; path=/"},
        "body": "<form></form>",
    }
    with patch.object(cve_2011_3416, "HttpClient") as client:
        client.return_value.get.return_value = page
        result = cve_2011_3416.check(
            "https://fixture.test",
            run_exploit_check=True,
            aspnet_runtime=RUNTIME,
            timeout=1,
        )
    assert result.exploit_ran is False
    assert "passive-only" in result.detail
