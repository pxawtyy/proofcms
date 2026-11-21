from unittest.mock import patch

from proofcms.modules.generic import cve_2025_53772 as webdeploy


def test_metadata_is_passive():
    meta = webdeploy.metadata()
    assert meta["cve"] == "CVE-2025-53772"
    assert meta["exploit_modes"] == []
    assert meta["intrusive"] is False
    assert meta["affected_versions"] == ["10.0.2000"]


def test_classify_webdeploy_versions():
    assert webdeploy.classify_version("10.0.2000") == "LIKELY_VULNERABLE"
    assert webdeploy.classify_version("10.0.2001") == "PATCHED"
    assert webdeploy.classify_version("10.0.2002") == "PATCHED"
    assert webdeploy.classify_version("9.0.0") == "DETECTED_VERSION_UNKNOWN"
    assert webdeploy.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_generic_iis_404_is_not_detected():
    response = {"status": 404, "body": "Not Found", "headers": {"Server": "Microsoft-IIS/10.0"}}
    with patch.object(webdeploy.HttpClient, "get", return_value=response):
        finding = webdeploy.check("https://fixture.test", timeout=1)
    assert finding.status == "NOT_DETECTED"
    assert finding.evidence["surface"] is None


def test_msdeploy_auth_surface_is_likely_vulnerable():
    surface = {"status": 401, "body": "", "headers": {"Server": "Microsoft-IIS/10.0"}}
    probe = {"status": 401, "missing_sync_options": False, "auth_required": True, "body_hash": "auth"}
    with (
        patch.object(webdeploy.HttpClient, "get", return_value=surface),
        patch.object(webdeploy.HttpClient, "request", return_value=probe),
    ):
        finding = webdeploy.check("https://fixture.test", timeout=1)
    assert finding.status == "LIKELY_VULNERABLE"
    assert finding.confidence == "HIGH"
    assert finding.evidence["safe_probe"]["auth_required"] is True


def test_safe_probe_missing_sync_options_confirms_handler():
    surface = {"status": 400, "body": "MSDeploy", "headers": {"Server": "Microsoft-IIS/10.0"}}
    response = {"status": 400, "body": "MSDeploy.SyncOptions is required", "headers": {}}
    with (
        patch.object(webdeploy.HttpClient, "get", return_value=surface),
        patch.object(webdeploy.HttpClient, "request", return_value=response),
    ):
        finding = webdeploy.check("https://fixture.test", timeout=1)
    assert finding.status == "LIKELY_VULNERABLE"
    assert finding.confidence == "HIGH"
    assert finding.evidence["safe_probe"]["missing_sync_options"] is True
    assert "no serialized payload was sent" in finding.detail


def test_known_patched_build_is_patched():
    surface = {"status": 401, "body": "", "headers": {"Server": "Microsoft-IIS/10.0"}}
    probe = {"status": 401, "missing_sync_options": False, "auth_required": True, "body_hash": "auth"}
    with (
        patch.object(webdeploy.HttpClient, "get", return_value=surface),
        patch.object(webdeploy.HttpClient, "request", return_value=probe),
    ):
        finding = webdeploy.check("https://fixture.test", webdeploy_version="10.0.2001", timeout=1)
    assert finding.status == "PATCHED"
    assert finding.confidence == "HIGH"


def test_core_cms_version_is_not_a_webdeploy_build():
    surface = {"status": 401, "body": "", "headers": {"Server": "Microsoft-IIS/10.0"}}
    probe = {"status": 401, "missing_sync_options": False, "auth_required": True, "body_hash": "auth"}
    with (
        patch.object(webdeploy.HttpClient, "get", return_value=surface),
        patch.object(webdeploy.HttpClient, "request", return_value=probe),
    ):
        finding = webdeploy.check("https://fixture.test", cms_version="6.7.0", timeout=1)
    assert finding.status == "LIKELY_VULNERABLE"
    assert finding.component_version is None


def test_exploit_request_is_passive_only():
    surface = {"status": 401, "body": "", "headers": {"Server": "Microsoft-IIS/10.0"}}
    probe = {"status": 401, "missing_sync_options": False, "auth_required": True, "body_hash": "auth"}
    with (
        patch.object(webdeploy.HttpClient, "get", return_value=surface),
        patch.object(webdeploy.HttpClient, "request", return_value=probe),
    ):
        finding = webdeploy.check("https://fixture.test", run_exploit_check=True, timeout=1)
    assert finding.exploit_ran is False
    assert "passive-only" in finding.detail
