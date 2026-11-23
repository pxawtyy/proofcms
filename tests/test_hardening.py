from __future__ import annotations

import argparse
from unittest.mock import patch

import pytest
import requests
from requests.exceptions import InvalidURL

from proofcms.cli import _rate_limit_arg
from proofcms.core.categories import classify_vulnerability_type
from proofcms.core.http import _PolicySession, _redirect_allowed, build_multipart
from proofcms.core.redact import redact_output, redact_url
from proofcms.core.versions import version_in_specifier
from proofcms.detectors import nginx, node, php
from proofcms.reporting.sarif import build_sarif_report


def test_redirect_policy_blocks_public_to_private_pivot():
    assert not _redirect_allowed("https://target.example", "http://127.0.0.1/")
    assert not _redirect_allowed("https://target.example", "http://169.254.169.254/latest/")
    assert not _redirect_allowed("https://target.example", "file:///etc/passwd")


def test_redirect_policy_keeps_lab_and_public_redirects():
    assert _redirect_allowed("http://127.0.0.1:8080/", "http://127.0.0.1:9090/")
    assert _redirect_allowed("https://target.example", "https://cdn.example/asset")


def test_policy_session_blocks_a_private_redirect():
    response = requests.Response()
    response.status_code = 302
    response.url = "https://target.example/start"
    response.headers["location"] = "http://127.0.0.1/"
    with pytest.raises(InvalidURL):
        _PolicySession().get_redirect_target(response)


def test_multipart_rejects_header_injection():
    with pytest.raises(ValueError):
        build_multipart({}, {"file": ("a\r\nX-Injected: 1", b"x", "text/plain")})


def test_multipart_encodes_non_latin1_filename():
    _, body = build_multipart({}, {"file": ("ファイル.txt", b"x", "text/plain")})
    assert b"filename*=UTF-8''%E3%83%95%E3%82%A1%E3%82%A4%E3%83%AB.txt" in body


def test_prerelease_versions_are_evaluated_against_upper_bounds():
    assert version_in_specifier("1.5.21-rc1", "<=1.5.21") is True
    assert version_in_specifier("1.5.21-rc1", "<1.5.22") is True


def test_category_lookup_is_case_insensitive():
    assert classify_vulnerability_type("cve-2015-7297") == "SQL Injection"


def test_node_detector_does_not_match_an_envoy_banner():
    class Client:
        def get(self, path):
            return {"status": 200, "headers": {"Server": "Envoy v1.28.0"}, "body": ""}

    with patch.object(node, "HttpClient", return_value=Client()):
        info = node.detect_node_runtime("https://target.test")
    assert info.detected is False


def test_node_detector_still_matches_node_banner():
    class Client:
        def get(self, path):
            return {"status": 200, "headers": {"Server": "Node.js/18.19.0"}, "body": ""}

    with patch.object(node, "HttpClient", return_value=Client()):
        info = node.detect_node_runtime("https://target.test")
    assert info.detected is True
    assert info.version == "18.19.0"


def test_nginx_detector_ignores_version_text_in_html():
    class Client:
        def get(self, path):
            return {"status": 200, "headers": {"Server": "cloudflare"}, "body": "nginx/1.26.3"}

    with patch.object(nginx, "HttpClient", return_value=Client()):
        info = nginx.detect_nginx_runtime("https://target.test")
    assert info.detected is False


def test_sarif_marks_failed_execution_and_redacts():
    report = {
        "tool": "ProofCMS",
        "tool_version": "2.1.0",
        "summary_by_status": {"ERROR": 1},
        "targets": [
            {
                "target": "https://user:pass@target.example/?token=secret#frag",
                "results": [],
            }
        ],
    }
    sarif = build_sarif_report(report)
    invocation = sarif["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    serialized = str(sarif)
    assert "user:pass" not in serialized
    assert "secret" not in serialized


def test_redaction_covers_fragments_proxy_credentials_and_composite_keys():
    assert "secret" not in redact_url("https://target.example/path#secret")
    assert redact_url("socks5://user:pass@proxy.example:1080") == "socks5://***@proxy.example:1080"
    output = redact_output(
        {
            "admin_password": "a",
            "session_cookie": "b",
            "nested": {"csrf_token": "c"},
        }
    )
    assert output == {
        "admin_password": "***",
        "session_cookie": "***",
        "nested": {"csrf_token": "***"},
    }


def test_php_origin_probe_is_opt_in():
    phpinfo = (
        "<html><head><title>PHP 7.4.33 - phpinfo()</title></head><body>"
        "<tr><td>PHP Version</td><td>7.4.33</td></tr>"
        "<tr><td>SERVER_ADDR</td><td>190.89.239.242</td></tr>"
        "</body></html>"
    )

    class Client:
        def __init__(self, *args, **kwargs):
            pass

        def get(self, path, **kwargs):
            if path == "phpinfo.php":
                return {"status": 200, "body": phpinfo, "body_len": len(phpinfo)}
            return {"status": 404, "body": "", "headers": {}}

    baseline = {"status": 404, "body_hash": "missing", "normalized_body_hash": "missing"}
    with (
        patch.object(php, "HttpClient", Client),
        patch.object(php, "probe_target_baseline", return_value=baseline),
        patch.object(php, "_probe_disclosed_origin", return_value=(True, "nginx")) as probe,
    ):
        php.detect_php_runtime("https://target.test", timeout=1)
        probe.assert_not_called()

    with (
        patch.object(php, "HttpClient", Client),
        patch.object(php, "probe_target_baseline", return_value=baseline),
        patch.object(php, "_probe_disclosed_origin", return_value=(True, "nginx")) as probe,
    ):
        php.detect_php_runtime("https://target.test", timeout=1, probe_disclosed_origin=True)
        probe.assert_called_once()


def test_rate_limit_rejects_invalid_values():
    for value in ("-1", "nan", "inf"):
        with pytest.raises(argparse.ArgumentTypeError):
            _rate_limit_arg(value)
    assert _rate_limit_arg("0") == 0.0
    assert _rate_limit_arg("2.5") == 2.5


def test_text_report_does_not_overwrite(tmp_path):
    from proofcms.reporting.text import write_text_report

    first = write_text_report(tmp_path / "report.txt", {"targets": []}, [])
    second = write_text_report(tmp_path / "report.txt", {"targets": []}, [])
    assert first.name == "report.txt"
    assert second.name == "report_1.txt"


def test_json_report_requires_explicit_overwrite(tmp_path):
    from proofcms.reporting.json import write_json_report

    path = tmp_path / "report.json"
    write_json_report(path, {"targets": []})
    with pytest.raises(FileExistsError):
        write_json_report(path, {"targets": []})
    write_json_report(path, {"targets": []}, overwrite=True)


def test_sanitize_argv_redacts_sensitive_flags_and_values():
    from proofcms.reporting.console import sanitize_argv

    sanitized = sanitize_argv(
        ["--password", "hunter2", "--session-cookie=abc", "--proxy", "socks5://u:p@h:1"]
    )
    assert "hunter2" not in sanitized
    assert "--password" in sanitized
    assert "--session-cookie=***" in sanitized
    assert "socks5://u:p@h:1" not in sanitized
