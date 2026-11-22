from __future__ import annotations

from unittest.mock import patch

import pytest

from proofcms.detectors.nginx import detect_nginx_runtime
from proofcms.modules.generic import (
    cve_2026_9256,
    cve_2026_42055,
    cve_2026_42530,
    cve_2026_42533,
    cve_2026_42945,
    cve_2026_56434,
    cve_2026_60005,
    cve_2026_90439,
    cve_2026_113425,
    cve_2026_121810,
    cve_2026_123007,
    cve_2026_123633,
    cve_2026_123634,
)


def test_nginx_detector_reads_version_and_http3_advertisement():
    response = {
        "status": 200,
        "body": "ok",
        "headers": {"Server": "nginx/1.31.1", "Alt-Svc": 'h3=":443"; ma=86400'},
    }
    with patch("proofcms.detectors.nginx.HttpClient.get", return_value=response):
        runtime = detect_nginx_runtime("https://fixture.test", timeout=1)
    assert runtime.detected is True
    assert runtime.version == "1.31.1"
    assert runtime.http3_advertised is True
    assert runtime.edge_server is None


def test_nginx_detector_reads_origin_version_from_phpinfo_behind_cloudflare():
    responses = [
        {
            "status": 200,
            "body": "<html>Portal do Zacarias</html>",
            "headers": {"Server": "cloudflare", "Alt-Svc": 'h3=":443"; ma=86400'},
        },
        {
            "status": 200,
            "body": (
                "<html><head><title>PHP 7.4.33 - phpinfo()</title></head><body>"
                "<table><tr><td class='e'>$_SERVER['SERVER_SOFTWARE']</td>"
                "<td class='v'>nginx/1.26.3</td></tr></table></body></html>"
            ),
            "headers": {"Server": "cloudflare"},
        },
    ]
    with patch("proofcms.detectors.nginx.HttpClient.get", side_effect=responses) as get:
        runtime = detect_nginx_runtime("https://fixture.test/site/", timeout=1)
    assert [call.args[0] for call in get.call_args_list] == ["/", "phpinfo.php"]
    assert runtime.detected is True
    assert runtime.version == "1.26.3"
    assert runtime.source == "/phpinfo.php:SERVER_SOFTWARE"
    assert runtime.server == "nginx/1.26.3"
    assert runtime.http3_advertised is False
    assert runtime.edge_server == "cloudflare"
    assert runtime.edge_http3_advertised is True


def test_nginx_detector_rejects_fake_phpinfo_content():
    responses = [
        {"status": 200, "body": "ok", "headers": {"Server": "cloudflare"}},
        {
            "status": 200,
            "body": "Documentation mentioning SERVER_SOFTWARE nginx/1.26.3",
            "headers": {"Server": "cloudflare"},
        },
    ]
    with patch("proofcms.detectors.nginx.HttpClient.get", side_effect=responses):
        runtime = detect_nginx_runtime("https://fixture.test/site/", timeout=1)
    assert runtime.detected is False
    assert runtime.version is None


@pytest.mark.parametrize(
    ("module", "vulnerable", "fixed"),
    [
        (cve_2026_42945, "1.30.0", "1.30.1"),
        (cve_2026_9256, "1.31.0", "1.31.1"),
        (cve_2026_42055, "1.31.1", "1.31.2"),
        (cve_2026_42530, "1.31.1", "1.31.2"),
        (cve_2026_42533, "1.31.2", "1.31.3"),
        (cve_2026_56434, "1.31.2", "1.31.3"),
        (cve_2026_60005, "1.31.2", "1.31.3"),
        (cve_2026_90439, "1.31.5", "1.31.6"),
        (cve_2026_123633, "1.31.8", "1.31.9"),
        (cve_2026_123007, "1.31.8", "1.31.9"),
        (cve_2026_123634, "1.31.8", "1.31.9"),
        (cve_2026_121810, "1.31.8", "1.31.9"),
        (cve_2026_113425, "1.31.8", "1.31.9"),
    ],
)
def test_nginx_advisory_version_boundaries(module, vulnerable, fixed):
    assert module.classify_version(vulnerable) == "LIKELY_VULNERABLE"
    assert module.classify_version(fixed) == "PATCHED"


def test_nginx_stable_branch_backport_boundaries():
    assert cve_2026_9256.classify_version("1.30.1") == "LIKELY_VULNERABLE"
    assert cve_2026_9256.classify_version("1.30.2") == "PATCHED"
    assert cve_2026_42055.classify_version("1.30.2") == "LIKELY_VULNERABLE"
    assert cve_2026_42055.classify_version("1.30.3") == "PATCHED"
    assert cve_2026_42533.classify_version("1.30.3") == "LIKELY_VULNERABLE"
    assert cve_2026_42533.classify_version("1.30.4") == "PATCHED"
    assert cve_2026_56434.classify_version("1.30.4") == "PATCHED"
    assert cve_2026_60005.classify_version("1.30.4") == "PATCHED"
    assert cve_2026_90439.classify_version("1.30.4") == "LIKELY_VULNERABLE"
    assert cve_2026_90439.classify_version("1.30.5") == "PATCHED"


def test_new_nginx_lower_boundaries_are_not_affected():
    assert cve_2026_42533.classify_version("0.9.5") == "NOT_AFFECTED"
    assert cve_2026_56434.classify_version("0.8.10") == "NOT_AFFECTED"
    assert cve_2026_60005.classify_version("1.15.7") == "NOT_AFFECTED"
    assert cve_2026_90439.classify_version("1.29.1") == "NOT_AFFECTED"
    assert cve_2026_123633.classify_version("1.19.6") == "NOT_AFFECTED"
    assert cve_2026_123007.classify_version("1.9.4") == "NOT_AFFECTED"
    assert cve_2026_123634.classify_version("1.13.3") == "NOT_AFFECTED"
    assert cve_2026_121810.classify_version("1.24.9") == "NOT_AFFECTED"
    assert cve_2026_113425.classify_version("0.5.14") == "NOT_AFFECTED"


def test_config_dependent_nginx_cve_lower_bounds():
    assert cve_2026_123634.classify_version("1.13.4") == "LIKELY_VULNERABLE"
    assert cve_2026_121810.classify_version("1.25.0") == "LIKELY_VULNERABLE"
    assert cve_2026_113425.classify_version("0.5.15") == "LIKELY_VULNERABLE"


def test_nginx3_upstream_cve_requires_observable_h3_path():
    runtime = {
        "detected": True,
        "version": "1.31.8",
        "source": "/:Server",
        "server": "nginx/1.31.8",
        "http3_advertised": False,
    }
    result = cve_2026_121810.check("https://fixture.test", nginx_runtime=runtime)
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["http3_advertised"] is False

    runtime["http3_advertised"] = True
    result = cve_2026_121810.check("https://fixture.test", nginx_runtime=runtime)
    assert result.status == "LIKELY_VULNERABLE"
    assert result.confidence == "HIGH"


def test_config_dependent_nginx_cves_have_no_active_probe():
    runtime = {
        "detected": True,
        "version": "1.31.8",
        "source": "/:Server",
        "server": "nginx/1.31.8",
    }
    for module in (cve_2026_123634, cve_2026_113425):
        result = module.check(
            "https://fixture.test", run_exploit_check=True, nginx_runtime=runtime
        )
        assert result.exploit_ran is False
        assert "not visible" in result.detail


def test_window_underflow_cve_stable_and_mainline_boundaries():
    assert cve_2026_123007.classify_version("1.9.5") == "LIKELY_VULNERABLE"
    assert cve_2026_123007.classify_version("1.30.6") == "LIKELY_VULNERABLE"
    assert cve_2026_123007.classify_version("1.30.7") == "PATCHED"
    assert cve_2026_123007.classify_version("1.31.8") == "LIKELY_VULNERABLE"
    assert cve_2026_123007.classify_version("1.31.9") == "PATCHED"


def test_window_underflow_cve_requires_observable_h2_path():
    runtime = {
        "detected": True,
        "version": "1.31.8",
        "source": "/:Server",
        "server": "nginx/1.31.8",
        "http2_enabled": False,
    }
    result = cve_2026_123007.check("https://fixture.test", nginx_runtime=runtime)
    assert result.status == "NOT_CONFIRMED"
    assert result.vulnerability_type == "Memory Corruption"
    assert result.evidence["http2_enabled"] is False

    runtime["http2_enabled"] = True
    result = cve_2026_123007.check("https://fixture.test", nginx_runtime=runtime)
    assert result.status == "LIKELY_VULNERABLE"
    assert result.confidence == "HIGH"
    assert result.evidence["http2_enabled"] is True


def test_window_underflow_cve_has_no_active_probe():
    runtime = {
        "detected": True,
        "version": "1.31.8",
        "source": "/:Server",
        "server": "nginx/1.31.8",
        "http2_enabled": True,
    }
    result = cve_2026_123007.check(
        "https://fixture.test", run_exploit_check=True, nginx_runtime=runtime
    )
    assert result.exploit_ran is False
    assert "could crash" in result.detail


def test_http2_cve_stable_and_mainline_boundaries():
    assert cve_2026_123633.classify_version("1.19.7") == "LIKELY_VULNERABLE"
    assert cve_2026_123633.classify_version("1.30.6") == "LIKELY_VULNERABLE"
    assert cve_2026_123633.classify_version("1.30.7") == "PATCHED"
    assert cve_2026_123633.classify_version("1.31.8") == "LIKELY_VULNERABLE"
    assert cve_2026_123633.classify_version("1.31.9") == "PATCHED"


def test_http2_cve_requires_observable_h2_path():
    runtime = {
        "detected": True,
        "version": "1.31.8",
        "source": "/:Server",
        "server": "nginx/1.31.8",
        "http2_enabled": False,
    }
    result = cve_2026_123633.check("https://fixture.test", nginx_runtime=runtime)
    assert result.status == "NOT_CONFIRMED"
    assert result.vulnerability_type == "Memory Corruption"
    assert result.evidence["http2_enabled"] is False

    runtime["http2_enabled"] = True
    result = cve_2026_123633.check("https://fixture.test", nginx_runtime=runtime)
    assert result.status == "LIKELY_VULNERABLE"
    assert result.confidence == "HIGH"
    assert result.evidence["http2_enabled"] is True


def test_http2_cve_has_no_active_probe():
    runtime = {
        "detected": True,
        "version": "1.31.8",
        "source": "/:Server",
        "server": "nginx/1.31.8",
        "http2_enabled": True,
    }
    result = cve_2026_123633.check(
        "https://fixture.test", run_exploit_check=True, nginx_runtime=runtime
    )
    assert result.exploit_ran is False
    assert "could crash" in result.detail


def test_nginx_detector_records_alpn_http2_for_origin_only():
    response = {
        "status": 200,
        "body": "ok",
        "headers": {"Server": "nginx/1.31.8"},
    }
    with patch("proofcms.detectors.nginx.HttpClient.get", return_value=response), patch(
        "proofcms.detectors.nginx._origin_http2_enabled", return_value=True
    ):
        runtime = detect_nginx_runtime("https://fixture.test", timeout=1)
    assert runtime.http2_enabled is True


def test_http2_alpn_probe_skips_proxy_and_plaintext():
    from proofcms.detectors.nginx import _origin_http2_enabled

    assert _origin_http2_enabled("https://fixture.test", 1, "http://proxy.test:8080") is False
    assert _origin_http2_enabled("http://fixture.test", 1, None) is False


def test_http3_cve_requires_observable_http3_path():
    runtime = {
        "detected": True,
        "version": "1.31.1",
        "source": "/:Server",
        "server": "nginx/1.31.1",
        "http3_advertised": False,
    }
    result = cve_2026_42530.check("https://fixture.test", nginx_runtime=runtime)
    assert result.status == "NOT_CONFIRMED"
    assert result.vulnerability_type == "Memory Corruption"

    runtime["http3_advertised"] = True
    result = cve_2026_42530.check("https://fixture.test", nginx_runtime=runtime)
    assert result.status == "LIKELY_VULNERABLE"
    assert result.confidence == "HIGH"


def test_new_http3_cve_requires_origin_http3_not_edge_http3():
    runtime = {
        "detected": True,
        "version": "1.31.5",
        "source": "/phpinfo.php:SERVER_SOFTWARE",
        "server": "nginx/1.31.5",
        "http3_advertised": False,
        "edge_server": "cloudflare",
        "edge_http3_advertised": True,
    }
    result = cve_2026_90439.check("https://fixture.test", nginx_runtime=runtime)
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["edge_http3_advertised"] is True

    runtime["http3_advertised"] = True
    result = cve_2026_90439.check("https://fixture.test", nginx_runtime=runtime)
    assert result.status == "LIKELY_VULNERABLE"
    assert result.confidence == "HIGH"


def test_slice_disclosure_has_correct_category():
    runtime = {
        "detected": True,
        "version": "1.31.2",
        "source": "/:Server",
        "server": "nginx/1.31.2",
        "http3_advertised": False,
    }
    result = cve_2026_60005.check("https://fixture.test", nginx_runtime=runtime)
    assert result.status == "NOT_CONFIRMED"
    assert result.vulnerability_type == "Information Disclosure"


def test_private_nginx_configuration_is_required_for_likely_status():
    runtime = {
        "detected": True,
        "version": "1.26.3",
        "source": "/phpinfo.php:SERVER_SOFTWARE",
        "server": "nginx/1.26.3",
        "http3_advertised": False,
    }
    modules = (
        cve_2026_9256,
        cve_2026_42055,
        cve_2026_42533,
        cve_2026_42945,
        cve_2026_56434,
        cve_2026_60005,
        cve_2026_123633,
        cve_2026_123007,
        cve_2026_123634,
        cve_2026_113425,
    )
    results = [module.check("https://fixture.test", nginx_runtime=runtime) for module in modules]
    assert all(result.status == "NOT_CONFIRMED" for result in results)
    assert all("cannot prove the private configuration" in result.detail for result in results)


def test_nginx_memory_proofs_remain_passive():
    runtime = {
        "detected": True,
        "version": "1.30.0",
        "source": "/:Server",
        "server": "nginx/1.30.0",
        "http3_advertised": False,
    }
    result = cve_2026_42945.check(
        "https://fixture.test", run_exploit_check=True, nginx_runtime=runtime
    )
    assert result.exploit_ran is False
    assert "could crash a worker" in result.detail


def test_42055_length_limit_status_differential():
    with patch.object(cve_2026_42055, "_status", side_effect=[502, 502, 502]):
        result = cve_2026_42055.run_aggressive_probe("https://fixture.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["above_status"] == 502
    assert result.evidence["above_differs"] is False

    with patch.object(cve_2026_42055, "_status", side_effect=[502, 502, 500]):
        result = cve_2026_42055.run_aggressive_probe("https://fixture.test")
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["above_differs"] is True


def test_42055_check_requires_aggressive_mode():
    runtime = {"detected": True, "version": "1.30.2", "server": "nginx/1.30.2"}
    result = cve_2026_42055.check(
        "https://fixture.test",
        run_exploit_check=True,
        exploit_mode="safe",
        nginx_runtime=runtime,
    )
    assert result.exploit_ran is False
    assert "isolated-lab aggressive" in result.detail
