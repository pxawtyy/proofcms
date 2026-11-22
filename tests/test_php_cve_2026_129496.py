from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.php import cve_2026_129496 as tz


class _FakeSession:
    def __init__(
        self,
        baseline: bool = True,
        probe: str = "crash",
        followup: str = "alive",
    ) -> None:
        self.baseline = baseline
        self.probe = probe
        self.followup = followup
        self.probed = False
        self.transcript: list[dict] = []

    def get(self, url: str, timeout: int | None = None) -> dict[str, object]:
        if "a=1&b=2" in url:
            self.probed = True
            if self.probe == "transport":
                return {"status": 0, "error": {"type": "TransportError", "message": "boom"}}
            if self.probe == "crash":
                return {"status": 500, "body": "PHP-CGI-CRASH\n"}
            return {"status": 200, "body": "OK\n"}
        if not self.baseline:
            return {"status": 404, "body": "Not Found"}
        if self.probed and self.followup == "dead":
            return {"status": 0, "error": {"type": "TransportError", "message": "dead"}}
        return {
            "status": 200,
            "body": "OK\n<br />Warning: PHP Startup: Invalid date.timezone...",
            "headers": {"X-Powered-By": ["PHP/8.5.12"]},
        }


def test_129496_classify_branches():
    assert tz.classify_version("8.5.12") == "LIKELY_VULNERABLE"
    assert tz.classify_version("8.5.13") == "PATCHED"
    assert tz.classify_version("8.4.27") == "LIKELY_VULNERABLE"
    assert tz.classify_version("8.4.28") == "PATCHED"
    assert tz.classify_version("8.3.36") == "LIKELY_VULNERABLE"
    assert tz.classify_version("8.3.37") == "PATCHED"
    assert tz.classify_version("8.2.35") == "LIKELY_VULNERABLE"
    assert tz.classify_version("8.2.36") == "PATCHED"
    assert tz.classify_version("8.1.0") == "NOT_CONFIRMED"
    assert tz.classify_version("8.6.0") == "NOT_AFFECTED"
    assert tz.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_129496_passive_results():
    vulnerable = tz.passive_result({"detected": True, "version": "8.5.12"})
    assert vulnerable.status == "LIKELY_VULNERABLE"
    assert "file-based" in vulnerable.detail
    assert "max_input_vars" in vulnerable.detail

    patched = tz.passive_result({"detected": True, "version": "8.5.13"})
    assert patched.status == "PATCHED"

    legacy = tz.passive_result({"detected": True, "version": "8.1.0"})
    assert legacy.status == "NOT_CONFIRMED"
    assert legacy.evidence["package_backport_required"] is True

    unaffected = tz.passive_result({"detected": True, "version": "8.6.0"})
    assert unaffected.status == "NOT_AFFECTED"

    missing = tz.passive_result({"detected": False})
    assert missing.status == "NOT_DETECTED"


def test_129496_cgi_crash_confirms():
    fake = _FakeSession()
    with patch.object(tz, "HttpSession", return_value=fake):
        result = tz.run_aggressive_probe("http://127.0.0.1:9105")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["probe_status"] == 500
    assert result.evidence["probe_crash_marker"] is True
    assert result.evidence["followup_alive"] is True
    assert result.evidence["lab_php"] == "8.5.12"


def test_129496_fixed_probe_is_not_confirmed():
    fake = _FakeSession(probe="ok")
    with patch.object(tz, "HttpSession", return_value=fake):
        result = tz.run_aggressive_probe("http://127.0.0.1:9105")
    assert result.status == "NOT_CONFIRMED"
    assert result.confidence == "HIGH"
    assert result.evidence["probe_status"] == 200


def test_129496_missing_lab_app_is_not_confirmed():
    fake = _FakeSession(baseline=False)
    with patch.object(tz, "HttpSession", return_value=fake):
        result = tz.run_aggressive_probe("http://127.0.0.1:9105")
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["baseline_status"] == 404


def test_129496_crash_with_dead_followup_is_error():
    fake = _FakeSession(probe="crash", followup="dead")
    with patch.object(tz, "HttpSession", return_value=fake):
        result = tz.run_aggressive_probe("http://127.0.0.1:9105")
    assert result.status == "ERROR"
    assert result.confidence == "LOW"


def test_129496_transport_probe_with_alive_followup_confirms():
    fake = _FakeSession(probe="transport", followup="alive")
    with patch.object(tz, "HttpSession", return_value=fake):
        result = tz.run_aggressive_probe("http://127.0.0.1:9105")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"


def test_129496_check_aggressive_only_and_version_gate():
    with patch.object(tz, "HttpSession", return_value=_FakeSession()):
        safe = tz.check(
            "http://127.0.0.1:9105",
            php_runtime={"detected": True, "version": "8.5.12"},
            run_exploit_check=True,
            exploit_mode="safe",
        )
    assert safe.status == "LIKELY_VULNERABLE"
    assert "aggressive mode" in safe.detail

    with patch.object(tz, "HttpSession", return_value=_FakeSession()):
        aggressive = tz.check(
            "http://127.0.0.1:9105",
            php_runtime={"detected": True, "version": "8.5.12"},
            run_exploit_check=True,
            exploit_mode="aggressive",
        )
    assert aggressive.status == "VULNERABLE"

    patched = tz.check(
        "http://127.0.0.1:9105",
        php_runtime={"detected": True, "version": "8.5.13"},
        run_exploit_check=True,
        exploit_mode="aggressive",
    )
    assert patched.status == "PATCHED"


def test_129496_metadata_contract():
    meta = tz.metadata()
    assert meta["cve"] == "CVE-2026-129496"
    assert meta["cms"] == "php"
    assert meta["exploit_modes"] == ["aggressive"]
    assert meta["vulnerability_type"] == "Memory Corruption"
    assert "8.5.13" in meta["affected_rule"]
