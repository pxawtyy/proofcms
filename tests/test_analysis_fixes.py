import importlib
import json
import urllib.error
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from proofcms import cli
from proofcms.core.http import HttpClient, _build_response_dict, is_baseline_match, normalize_url, poll_paths
from proofcms.core.models import CMSInfo, PHPRuntimeInfo
from proofcms.detectors import joomla, php, wordpress
from proofcms.modules.joomla import cve_2026_48907
from proofcms.modules.joomla.k2_dangerous_extension import check_k2_dangerous_extension
from proofcms.reporting import redact_output, sanitize_argv, write_json_report


def response(body="", status=200, url="https://fixture.test/"):
    return _build_response_dict(status, body, url, url)


def test_transport_error_is_structured():
    client = HttpClient("https://fixture.test", timeout=1)
    with patch.object(client.opener, "open", side_effect=urllib.error.URLError("offline")):
        result = client.get("/")
    assert result["status"] == 0
    assert result["body"] == ""
    assert result["error"]["type"] == "URLError"


@pytest.mark.parametrize("value", ["unknown-build", "", None])
def test_invalid_jce_version_never_reports_patched(value):
    with patch.object(cve_2026_48907, "probe_jce", return_value={"found": True, "version": value}):
        assert cve_2026_48907.passive_check("https://fixture.test", None).status == "INCONCLUSIVE"


def test_invalid_k2_version_never_reports_patched():
    result = check_k2_dangerous_extension(
        cve="CVE-TEST", name="test", extension="phar", target_url="https://fixture.test",
        plugins={"k2": {"found": True, "version": "unknown-build"}}, run_exploit_check=False,
        exploit_mode="safe", timeout=1, proxy=None,
    )
    assert result.status == "INCONCLUSIVE"


def test_url_normalization_is_strict_and_pure():
    assert normalize_url("HTTPS://Example.COM/cms/") == "https://example.com/cms"
    with pytest.raises(ValueError):
        normalize_url("ftp://example.com")
    with pytest.raises(ValueError):
        normalize_url("https://example.com/?token=secret")
    assert HttpClient("https://example.com/cms")._resolve_url("/readme.html") == "https://example.com/cms/readme.html"


def test_reports_redact_nested_urls_and_secret_keys():
    value = {
        "target": "https://user:pass@example.com/path?token=secret&view=public",
        "evidence": {"password": "secret", "url": "https://example.com/?api_key=secret"},
    }
    redacted = redact_output(value)
    serialized = json.dumps(redacted)
    assert "user:pass@" not in serialized
    assert '"password": "secret"' not in serialized
    assert "token=secret" not in serialized
    assert "view=public" in redacted["target"]
    assert "pass" not in " ".join(sanitize_argv(["proofcms", "-u", value["target"]]))
    path = Path(f".proofcms-report-test-{uuid.uuid4().hex}.json")
    try:
        write_json_report(path, value)
        assert "secret" not in path.read_text(encoding="utf-8")
        with pytest.raises(FileExistsError):
            write_json_report(path, value)
    finally:
        path.unlink(missing_ok=True)


def test_wordpress_weak_homepage_continues_to_version_evidence():
    calls = []

    def fetch(url, **kwargs):
        calls.append(url)
        if url.endswith("/readme.html"):
            return response("<h1>WordPress</h1><br>Version 6.9.5")
        if url.endswith("/"):
            return response('<script src="/wp-content/plugins/demo/main.js"></script>')
        return response(status=404)

    with patch.object(wordpress, "_fetch", side_effect=fetch):
        info = wordpress.detect_wordpress("https://fixture.test", 1)
    assert info.version == "6.9.5"
    assert len(calls) >= 3


def test_generic_template_path_does_not_detect_joomla():
    def fetch(url, **kwargs):
        return response('<img src="/templates/store/logo.png">') if url.endswith("/") else response(status=404)

    with patch.object(joomla, "fetch_url", side_effect=fetch):
        assert not joomla.scan_joomla("https://fixture.test", 1).detected


def test_article_php_version_does_not_fingerprint_runtime():
    with patch.object(php.HttpClient, "get", return_value=response("Our guide uses PHP 8.1.0.")):
        assert not php.detect_php_runtime("https://fixture.test", 1).detected


def test_same_title_and_length_are_not_enough_for_baseline_match():
    baseline = response("<html><title>Portal</title><p>Missing page</p></html>")
    actual = response("<html><title>Portal</title><p>Account info</p></html>")
    assert not is_baseline_match(actual, baseline)


def test_polling_checks_deadline_between_paths():
    calls = []

    def fetch(path):
        calls.append(path)
        return {"status": 404}

    with patch("time.monotonic", side_effect=[0.0, 0.0, 0.0, 1.0]):
        poll_paths(fetch, ["/one", "/two"], deadline=0.5)
    assert calls == ["/one"]


def test_required_inventory_skips_common_detectors():
    args = SimpleNamespace(timeout=1, proxy=None, concurrency=1, inventory="required")
    with patch.object(joomla, "fetch_url") as fetch:
        result = joomla.detect_plugins("https://fixture.test", args, required_plugins=set())
    fetch.assert_not_called()
    assert result
    assert all(item["source"] == "not-queried" for item in result.values())


def test_unreachable_target_matches_fail_on_error():
    argv = ["proofcms", "-u", "https://fixture.test", "--cve", "none", "--no-text-report", "--fail-on", "error"]
    with (
        patch("sys.argv", argv),
        patch.object(cli, "load_targets", return_value=["https://fixture.test"]),
        patch.object(cli, "probe_target_baseline", return_value={"status": 0, "error": {"type": "URLError"}}),
        patch.object(cli, "detect_cms", return_value=CMSInfo("unknown", False, None, "error")),
        patch.object(cli, "detect_php_runtime", return_value=PHPRuntimeInfo(False, None, "error")),
    ):
        assert cli.main() == 5


def test_unknown_fail_on_value_is_rejected_before_target_loading():
    argv = ["proofcms", "-u", "https://fixture.test", "--cve", "none", "--fail-on", "typo"]
    with patch("sys.argv", argv), patch.object(cli, "load_targets") as load_targets:
        assert cli.main() == 1
    load_targets.assert_not_called()


def test_every_registered_module_has_consistent_metadata():
    for cve, module_name in cli.AVAILABLE_CVES.items():
        module = importlib.import_module(module_name)
        metadata = module.metadata()
        assert metadata["cve"] == cve
        assert metadata.get("name")
        assert metadata.get("affected_rule")
        assert callable(module.check)


@pytest.mark.parametrize("detector", [joomla.detect_pagebuilderck, joomla.detect_helixultimate])
def test_joomla_detectors_reject_reflected_probe_paths(detector):
    def fake_fetch(url, timeout, proxy=None):
        body = f'<html><title>Error</title><p>Requested URL: {url}</p></html>'
        return {"status": 200, "body": body, "content_type": "text/html", "final_url": url}

    with patch.object(joomla, "fetch_url", side_effect=fake_fetch):
        info = detector("https://fixture.test", 1)
    assert info.found is False


def test_baforms_rejects_reflected_upload_path():
    def fake_fetch(url, timeout, proxy=None):
        body = f'<html><p>Missing resource {url}</p></html>'
        return {"status": 200, "body": body, "content_type": "text/html", "final_url": url}

    with patch.object(joomla, "fetch_url", side_effect=fake_fetch):
        info = joomla.detect_baforms("https://fixture.test", 1)
    assert info.found is False


def test_php_runtime_detects_executed_empty_configuration():
    responses = {
        "/": {"status": 200, "body": "homepage", "body_hash": "home", "headers": {}},
        "/index.php": {"status": 200, "body": "homepage", "body_hash": "home", "headers": {}},
        "/administrator/index.php": {"status": 403, "body": "forbidden", "body_hash": "deny", "headers": {}},
        "/wp-login.php": {"status": 404, "body": "missing", "body_hash": "missing", "headers": {}},
        "/configuration.php": {"status": 200, "body": "", "body_hash": "empty", "headers": {}},
    }

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def get(self, path):
            if path.startswith("/_proofcms_missing_"):
                return {"status": 404, "body": "missing", "body_hash": "missing", "headers": {}}
            return responses[path]

    baseline = {"status": 200, "body_hash": "home", "normalized_body_hash": "home"}
    with (
        patch.object(php, "HttpClient", FakeClient),
        patch.object(php, "probe_target_baseline", return_value=baseline),
    ):
        info = php.detect_php_runtime("https://fixture.test", timeout=1)
    assert info.detected is True
    assert info.source == "/configuration.php:executed-empty"


def test_php_runtime_rejects_uniform_empty_php_catch_all():
    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def get(self, path):
            return {"status": 200, "body": "", "body_hash": "empty", "headers": {}}

    baseline = {"status": 200, "body_hash": "empty", "normalized_body_hash": "empty"}
    with (
        patch.object(php, "HttpClient", FakeClient),
        patch.object(php, "probe_target_baseline", return_value=baseline),
    ):
        info = php.detect_php_runtime("https://fixture.test", timeout=1)
    assert info.detected is False


def test_helix3_generic_ajax_envelope_is_not_success():
    from proofcms.modules.joomla.cve_2026_49049 import response_looks_successful

    generic = {
        "status": 200,
        "body": '{"success":true,"message":null,"messages":null,"data":[]}',
    }
    assert response_looks_successful(generic) is False
