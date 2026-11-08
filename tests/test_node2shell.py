from unittest.mock import patch

from proofcms.detectors.node import detect_node_runtime
from proofcms.modules.generic import cve_2026_111497


def test_node_detector_requires_explicit_node_evidence():
    response = {
        "status": 200,
        "body": "<html>static page</html>",
        "headers": {"Server": "node/24.22.0", "X-Powered-By": "Express"},
    }
    with patch("proofcms.detectors.node.HttpClient.get", return_value=response):
        runtime = detect_node_runtime("https://fixture.test", timeout=1)
    assert runtime.detected is True
    assert runtime.version == "24.22.0"
    assert runtime.framework == "Express"
    assert runtime.source == "/:Server"


def test_node_detector_does_not_guess_from_generic_html():
    response = {"status": 200, "body": "node.js is mentioned in documentation", "headers": {"Server": "nginx"}}
    with patch("proofcms.detectors.node.HttpClient.get", return_value=response):
        runtime = detect_node_runtime("https://fixture.test", timeout=1)
    assert runtime.detected is False


def test_node2shell_version_boundaries():
    assert cve_2026_111497.classify_version("22.23.3") == "LIKELY_VULNERABLE"
    assert cve_2026_111497.classify_version("22.23.4") == "PATCHED"
    assert cve_2026_111497.classify_version("24.22.0") == "LIKELY_VULNERABLE"
    assert cve_2026_111497.classify_version("24.22.1") == "PATCHED"
    assert cve_2026_111497.classify_version("25.8.2") == "LIKELY_VULNERABLE"


def test_node2shell_safe_probe_only_uses_tiny_differential():
    runtime = {
        "detected": True,
        "version": "24.22.0",
        "source": "/:Server",
        "server": "node/24.22.0",
        "framework": "Express",
    }
    responses = [
        {"status": 404, "body_hash": "valid", "error": None},
        {"status": 400, "body_hash": "truncated", "error": None},
    ]
    with patch("proofcms.modules.generic.cve_2026_111497.HttpClient.post", side_effect=responses) as post:
        result = cve_2026_111497.check(
            "https://fixture.test", run_exploit_check=True, node_runtime=runtime, timeout=1
        )
    assert result.status == "LIKELY_VULNERABLE"
    assert result.exploit_ran is True
    assert result.evidence["safe_probe"] is True
    assert result.evidence["differential"] is True
    assert len(post.call_args_list[0].kwargs["data"]) < 64


def test_node2shell_unknown_version_is_not_confirmed_without_probe():
    runtime = {"detected": True, "version": None, "source": "/:X-Powered-By", "framework": "Express"}
    result = cve_2026_111497.check("https://fixture.test", node_runtime=runtime)
    assert result.status == "DETECTED_VERSION_UNKNOWN"
    assert result.exploit_ran is False
