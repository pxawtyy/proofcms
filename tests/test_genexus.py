from unittest.mock import patch

from proofcms.detectors.genexus import detect_genexus
from proofcms.modules.generic import cve_2024_58288


def test_genexus_detector_recognizes_gxajax_and_gxcfg_version():
    home = {
        "status": 200,
        "headers": {"Set-Cookie": "GXState=abc; path=/"},
        "body": '<html><script src="/gxcfg.js"></script><a href="/gxajax.aspx">x</a></html>',
    }
    config = {"status": 200, "headers": {}, "body": 'gx.version = "9.7.2.10";'}
    with patch("proofcms.detectors.genexus.HttpClient.get", side_effect=[home, config]):
        info = detect_genexus("https://fixture.test", timeout=1)
    assert info["detected"] is True
    assert info["version"] == "9.7.2.10"
    assert info["source"] == "/gxcfg.js"
    assert "body:gxajax" in info["evidence"]
    assert "cookie:gxstate" in info["evidence"]


def test_genexus_detector_ignores_generic_mentions():
    home = {
        "status": 200,
        "headers": {},
        "body": "<html>We use GeneXus for documentation only.</html>",
    }
    with patch("proofcms.detectors.genexus.HttpClient.get", return_value=home):
        info = detect_genexus("https://fixture.test", timeout=1)
    assert info["detected"] is False
    assert info["version"] is None


def test_genexus_protection_server_97210_is_likely_vulnerable():
    result = cve_2024_58288.check(
        "https://fixture.test",
        genexus_info={"detected": True, "version": "9.7.2.10", "source": "/gxcfg.js", "evidence": []},
    )
    assert result.status == "LIKELY_VULNERABLE"
    assert result.confidence == "HIGH"
    assert result.exploit_available is False


def test_genexus_protection_server_unknown_version_is_inconclusive():
    result = cve_2024_58288.check(
        "https://fixture.test",
        genexus_info={"detected": True, "version": None, "source": "body", "evidence": []},
    )
    assert result.status == "INCONCLUSIVE"


def test_genexus_not_detected():
    result = cve_2024_58288.check(
        "https://fixture.test",
        genexus_info={"detected": False, "version": None, "source": "not-detected", "evidence": []},
    )
    assert result.status == "NOT_DETECTED"


def test_genexus_metadata_is_passive():
    metadata = cve_2024_58288.metadata()
    assert metadata["exploit_modes"] == []
    assert metadata["intrusive"] is False
    assert metadata["required_detectors"] == ["genexus"]
