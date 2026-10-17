from unittest.mock import patch

from proofcms.detectors.aspnet import detect_aspnet_runtime
from proofcms.modules.generic import cve_2018_8284, cve_2023_21722, cve_2023_36560, cve_2023_36899


def _response():
    return {
        "status": 200,
        "headers": {
            "X-AspNet-Version": "2.0.50727",
            "X-Powered-By": "ASP.NET",
            "Server": "Microsoft-IIS/7.5",
            "Set-Cookie": "ASP.NET_SessionId=abc; path=/; HttpOnly",
        },
        "body": (
            '<meta name="Generator" content="GeneXus C#">'
            '<meta name="Version" content="10.1.8-<build>">'
            '/* GeneXus C# Generator version 10.1.8-<build> Main DBMS: sqlserver */'
            '<script src="gxgral.js"></script>'
        ),
    }


def test_detects_aspnet_and_genexus_fingerprints():
    client = type("Client", (), {"get": lambda self, path: _response()})
    with patch("proofcms.detectors.aspnet.HttpClient", return_value=client()):
        info = detect_aspnet_runtime("https://target.test")
    assert info.detected is True
    assert info.version == "2.0.50727"
    assert info.genexus_detected is True
    assert info.genexus_version == "10.1.8-<build>"
    assert info.genexus_dbms == "sqlserver"
    assert info.session_secure is False


def test_detects_gene_xus_on_linked_application_subpath():
    portal = {"status": 200, "headers": {}, "body": '<a href="/portal/">Portal</a>'}
    app = _response()

    class Client:
        def get(self, path):
            return app if path == "/portal/" else portal

    with patch("proofcms.detectors.aspnet.HttpClient", return_value=Client()):
        info = detect_aspnet_runtime("https://target.test")
    assert info.genexus_detected is True
    assert "/:X-AspNet-Version" in info.source


def test_aspnet_cves_are_not_confirmed_from_header_only():
    runtime = {"detected": True, "version": "2.0.50727", "source": "/:X-AspNet-Version"}
    for module in (cve_2018_8284, cve_2023_21722, cve_2023_36560, cve_2023_36899):
        result = module.check("https://target.test", aspnet_runtime=runtime)
        assert result.status == "NOT_CONFIRMED"
        assert result.exploit_ran is False


def test_aspnet_cves_are_not_detected_without_runtime():
    result = cve_2023_36899.check("https://target.test", aspnet_runtime={})
    assert result.status == "NOT_DETECTED"
