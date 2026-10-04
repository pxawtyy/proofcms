from __future__ import annotations

from unittest.mock import patch

from proofcms.detectors.php import detect_php_runtime
from proofcms.modules.php import cve_2012_1823, cve_2019_11043, cve_2024_4577


class FakeClient:
    def __init__(self, *args, **kwargs):
        pass

    def get(self, path):
        return {
            "status": 200,
            "headers": {"X-Powered-By": "PHP/8.2.19", "Server": "Apache/2.4.58 (Win64)"},
            "body": "ok",
        }


def test_php_detector_reads_public_header():
    with patch("proofcms.detectors.php.HttpClient", FakeClient):
        runtime = detect_php_runtime("https://example.test")
    assert runtime.detected
    assert runtime.version == "8.2.19"
    assert runtime.server == "Apache/2.4.58 (Win64)"
    assert runtime.entrypoint == "/"


def test_php_runtime_version_boundaries():
    assert cve_2024_4577.classify_version("8.1.28") == "LIKELY_VULNERABLE"
    assert cve_2024_4577.classify_version("8.1.29") == "PATCHED"
    assert cve_2024_4577.classify_version("8.2.19") == "LIKELY_VULNERABLE"
    assert cve_2024_4577.classify_version("8.3.8") == "PATCHED"
    assert cve_2019_11043.classify_version("7.2.23") == "LIKELY_VULNERABLE"
    assert cve_2019_11043.classify_version("7.2.24") == "PATCHED"
    assert cve_2012_1823.classify_version("5.3.12") == "LIKELY_VULNERABLE"
    assert cve_2012_1823.classify_version("5.3.13") == "PATCHED"
    assert cve_2012_1823.classify_version("5.4.2") == "LIKELY_VULNERABLE"
    assert cve_2012_1823.classify_version("5.4.3") == "PATCHED"


def test_4577_safe_marker_confirmation():
    runtime = {
        "detected": True,
        "version": "8.2.19",
        "server": "Apache/2.4 (Win64)",
        "entrypoint": "/index.php",
    }
    with patch(
        "proofcms.modules.php.cve_2024_4577.harmless_cgi_marker_probe",
        return_value=(True, "https://example.test/index.php?proof", 200),
    ):
        result = cve_2024_4577.check("https://example.test", run_exploit_check=True, php_runtime=runtime)
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.exploit_ran


def test_4577_rejects_disclosed_linux_origin():
    result = cve_2024_4577.check(
        "https://example.test",
        php_runtime={"detected": True, "version": "7.4.33", "server": "Apache/2.4 (Debian)"},
    )
    assert result.status == "NOT_AFFECTED"


def test_fpm_rule_requires_nginx_when_server_is_disclosed():
    result = cve_2019_11043.check(
        "https://example.test",
        php_runtime={"detected": True, "version": "7.3.10", "server": "Apache/2.4"},
    )
    assert result.status == "NOT_AFFECTED"


def test_fpm_unknown_version_is_not_affected_on_disclosed_apache_origin():
    result = cve_2019_11043.check(
        "https://example.test",
        php_runtime={"detected": True, "version": None, "server": "Apache/2.4"},
    )
    assert result.status == "NOT_AFFECTED"
    assert result.confidence == "HIGH"
