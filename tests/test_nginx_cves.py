from __future__ import annotations

from unittest.mock import patch

import pytest

from proofcms.detectors.nginx import detect_nginx_runtime
from proofcms.modules.generic import cve_2026_9256, cve_2026_42055, cve_2026_42530, cve_2026_42945


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


@pytest.mark.parametrize(
    ("module", "vulnerable", "fixed"),
    [
        (cve_2026_42945, "1.30.0", "1.30.1"),
        (cve_2026_9256, "1.31.0", "1.31.1"),
        (cve_2026_42055, "1.31.1", "1.31.2"),
        (cve_2026_42530, "1.31.1", "1.31.2"),
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


def test_http3_cve_requires_observable_http3_path():
    runtime = {
        "detected": True,
        "version": "1.31.1",
        "source": "/:Server",
        "server": "nginx/1.31.1",
        "http3_advertised": False,
    }
    result = cve_2026_42530.check("https://fixture.test", nginx_runtime=runtime)
    assert result.status == "INCONCLUSIVE"
    assert result.vulnerability_type == "Memory Corruption"

    runtime["http3_advertised"] = True
    result = cve_2026_42530.check("https://fixture.test", nginx_runtime=runtime)
    assert result.status == "LIKELY_VULNERABLE"
    assert result.confidence == "HIGH"


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
