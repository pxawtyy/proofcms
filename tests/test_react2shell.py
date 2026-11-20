from unittest.mock import patch

from proofcms.modules.generic import cve_2025_55182 as react2shell


def test_metadata_registers_safe_and_aggressive_modes():
    meta = react2shell.metadata()
    assert meta["cve"] == "CVE-2025-55182"
    assert meta["exploit_modes"] == ["safe", "aggressive"]
    assert meta["intrusive"] is True
    assert "19.0.0" in meta["affected_versions"]


def test_detect_rsc_uses_app_router_marker():
    response = {
        "status": 200,
        "body": '<script>self.__next_f.push([1,"0:..."])</script>',
        "headers": {"Server": "Next.js", "X-Nextjs-Cache": "HIT"},
    }
    with patch.object(react2shell.HttpClient, "get", return_value=response):
        detected = react2shell.detect_rsc("https://fixture.test", timeout=1, proxy=None)
    assert detected["detected"] is True
    assert "next_f" in detected["markers"]


def test_detect_rsc_rejects_plain_html():
    response = {"status": 200, "body": "<html>static page</html>", "headers": {"Server": "nginx"}}
    with patch.object(react2shell.HttpClient, "get", return_value=response):
        detected = react2shell.detect_rsc("https://fixture.test", timeout=1, proxy=None)
    assert detected["detected"] is False


def test_safe_probe_confirms_vulnerable_digest_error():
    response = {
        "status": 500,
        "body": '0:{"a":"$@1","f":""}\n1:E{"digest":"123456789"}\n',
        "headers": {},
        "body_hash": "digest",
        "error": None,
    }
    with patch.object(react2shell.HttpClient, "request", return_value=response):
        probe = react2shell.safe_probe("https://fixture.test", timeout=1, proxy=None)
    assert probe["digest_error"] is True


def test_safe_probe_recognizes_patched_page():
    response = {"status": 200, "body": "<html>page</html>", "headers": {}, "body_hash": "page", "error": None}
    with patch.object(react2shell.HttpClient, "request", return_value=response):
        probe = react2shell.safe_probe("https://fixture.test", timeout=1, proxy=None)
    assert probe["digest_error"] is False


def test_check_safe_probe_marks_vulnerable():
    detected = {"detected": True, "markers": ["next_f"], "status": 200}
    probe = {"status": 500, "digest_error": True, "body_hash": "digest", "error": None}
    with (
        patch.object(react2shell, "detect_rsc", return_value=detected),
        patch.object(react2shell, "safe_probe", return_value=probe),
    ):
        finding = react2shell.check(
            "https://fixture.test",
            run_exploit_check=True,
            exploit_mode="safe",
            timeout=1,
        )
    assert finding.status == "VULNERABLE"
    assert finding.confidence == "CONFIRMED"
    assert finding.exploit_ran is True
    assert finding.evidence["digest_error"] is True


def test_check_aggressive_probe_marks_vulnerable_with_marker():
    detected = {"detected": True, "markers": ["next_f"], "status": 200}
    probe = {
        "marker": "PROOFCMS_55182_deadbeef",
        "status": 303,
        "redirect": "/pwned?output=PROOFCMS_55182_deadbeef;push",
        "confirmed": True,
        "body_hash": "redirect",
        "error": None,
    }
    with (
        patch.object(react2shell, "detect_rsc", return_value=detected),
        patch.object(react2shell, "aggressive_probe", return_value=probe),
    ):
        finding = react2shell.check(
            "https://fixture.test",
            run_exploit_check=True,
            exploit_mode="aggressive",
            timeout=1,
        )
    assert finding.status == "VULNERABLE"
    assert finding.confidence == "CONFIRMED"
    assert finding.exploit_ran is True
    assert "X-Action-Redirect" in finding.detail


def test_check_without_probe_is_not_confirmed():
    detected = {"detected": True, "markers": ["next_f"], "status": 200}
    with patch.object(react2shell, "detect_rsc", return_value=detected):
        finding = react2shell.check("https://fixture.test", timeout=1)
    assert finding.status == "NOT_CONFIRMED"
    assert finding.confidence == "MEDIUM"


def test_check_no_rsc_is_not_detected():
    detected = {"detected": False, "markers": [], "status": 200}
    with patch.object(react2shell, "detect_rsc", return_value=detected):
        finding = react2shell.check("https://fixture.test", timeout=1)
    assert finding.status == "NOT_DETECTED"
    assert finding.confidence == "LOW"
