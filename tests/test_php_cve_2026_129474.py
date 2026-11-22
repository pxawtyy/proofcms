from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.php import cve_2026_129474 as ghsa

VULN_BODY = (
    "Fatal error: Allowed memory size of 4194304 bytes exhausted "
    "(tried to allocate 2101248 bytes) in /var/www/html/index.php on line 15\n"
    "Stack trace:\n"
    "#0 /var/www/html/index.php(15): C::test(3, 4, 'aaaaaaaaaaaaaaa...', NULL, NULL)\n"
    "#1 {main}\n"
)
FIXED_BODY = (
    "Fatal error: Allowed memory size of 4194304 bytes exhausted "
    "(tried to allocate 2101248 bytes) in /var/www/html/index.php on line 15\n"
    "Stack trace:\n"
    "#0 /var/www/html/index.php(15): C::test(1, 2, 3, 4, 'aaaaaaaaaaaaaaa...')\n"
    "#1 {main}\n"
)


class _FakeSession:
    def __init__(
        self,
        baseline: bool = True,
        probe: str = "vulnerable",
        alive: bool = True,
    ) -> None:
        self.baseline = baseline
        self.probe = probe
        self.alive = alive
        self.probed = False
        self.transcript: list[dict] = []

    def get(self, url: str, timeout: int | None = None) -> dict[str, object]:
        if "probe=1" in url:
            self.probed = True
            if self.probe == "transport":
                return {"status": 0, "error": {"type": "TransportError", "message": "boom"}}
            body = VULN_BODY if self.probe == "vulnerable" else FIXED_BODY
            if self.probe == "none":
                body = "OK\n"
            return {"status": 200, "body": body}
        if not self.baseline:
            return {"status": 404, "body": "Not Found"}
        if self.probed and not self.alive:
            return {"status": 0, "error": {"type": "TransportError", "message": "dead"}}
        return {"status": 200, "body": "OK PHP=8.5.12\n"}


def test_129474_classify_version_boundaries():
    assert ghsa.classify_version("8.5.0") == "LIKELY_VULNERABLE"
    assert ghsa.classify_version("8.5.12") == "LIKELY_VULNERABLE"
    assert ghsa.classify_version("8.5.13") == "PATCHED"
    assert ghsa.classify_version("8.4.27") == "NOT_AFFECTED"
    assert ghsa.classify_version("8.6.0") == "NOT_AFFECTED"
    assert ghsa.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_129474_passive_vulnerable_and_patched():
    vulnerable = ghsa.passive_result({"detected": True, "version": "8.5.12"})
    assert vulnerable.status == "LIKELY_VULNERABLE"
    assert "zend.exception_ignore_args" in vulnerable.detail

    patched = ghsa.passive_result({"detected": True, "version": "8.5.13"})
    assert patched.status == "PATCHED"

    unaffected = ghsa.passive_result({"detected": True, "version": "8.4.27"})
    assert unaffected.status == "NOT_AFFECTED"

    missing = ghsa.passive_result({"detected": False})
    assert missing.status == "NOT_DETECTED"


def test_129474_vulnerable_backtrace_confirms():
    fake = _FakeSession(probe="vulnerable")
    with patch.object(ghsa, "HttpSession", return_value=fake):
        result = ghsa.run_aggressive_probe("http://127.0.0.1:9103")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert "C::test(3, 4" in result.evidence["backtrace_line"]
    assert result.evidence["stale_backtrace"] is True
    assert result.evidence["fixed_backtrace"] is False
    assert result.evidence["lab_php"] == "8.5.12"


def test_129474_fixed_backtrace_is_not_confirmed():
    fake = _FakeSession(probe="fixed")
    with patch.object(ghsa, "HttpSession", return_value=fake):
        result = ghsa.run_aggressive_probe("http://127.0.0.1:9103")
    assert result.status == "NOT_CONFIRMED"
    assert result.confidence == "HIGH"
    assert result.evidence["fixed_backtrace"] is True
    assert result.evidence["stale_backtrace"] is False


def test_129474_missing_lab_app_is_not_confirmed():
    fake = _FakeSession(baseline=False)
    with patch.object(ghsa, "HttpSession", return_value=fake):
        result = ghsa.run_aggressive_probe("http://127.0.0.1:9103")
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["baseline_status"] == 404


def test_129474_worker_death_with_alive_control_confirms():
    fake = _FakeSession(probe="transport", alive=True)
    with patch.object(ghsa, "HttpSession", return_value=fake):
        result = ghsa.run_aggressive_probe("http://127.0.0.1:9103")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"


def test_129474_worker_death_with_dead_control_is_error():
    fake = _FakeSession(probe="transport", alive=False)
    with patch.object(ghsa, "HttpSession", return_value=fake):
        result = ghsa.run_aggressive_probe("http://127.0.0.1:9103")
    assert result.status == "ERROR"
    assert result.confidence == "LOW"


def test_129474_no_fatal_is_not_confirmed():
    fake = _FakeSession(probe="none")
    with patch.object(ghsa, "HttpSession", return_value=fake):
        result = ghsa.run_aggressive_probe("http://127.0.0.1:9103")
    assert result.status == "NOT_CONFIRMED"


def test_129474_check_aggressive_only_and_version_gate():
    with patch.object(ghsa, "HttpSession", return_value=_FakeSession()):
        safe = ghsa.check(
            "http://127.0.0.1:9103",
            php_runtime={"detected": True, "version": "8.5.12"},
            run_exploit_check=True,
            exploit_mode="safe",
        )
    assert safe.status == "LIKELY_VULNERABLE"
    assert "aggressive mode" in safe.detail

    with patch.object(ghsa, "HttpSession", return_value=_FakeSession()):
        aggressive = ghsa.check(
            "http://127.0.0.1:9103",
            php_runtime={"detected": True, "version": "8.5.12"},
            run_exploit_check=True,
            exploit_mode="aggressive",
        )
    assert aggressive.status == "VULNERABLE"

    patched = ghsa.check(
        "http://127.0.0.1:9103",
        php_runtime={"detected": True, "version": "8.5.13"},
        run_exploit_check=True,
        exploit_mode="aggressive",
    )
    assert patched.status == "PATCHED"


def test_129474_metadata_contract():
    meta = ghsa.metadata()
    assert meta["cve"] == "CVE-2026-129474"
    assert meta["cms"] == "php"
    assert meta["exploit_modes"] == ["aggressive"]
    assert meta["vulnerability_type"] == "Memory Corruption"
    assert "8.5.13" in meta["affected_rule"]
