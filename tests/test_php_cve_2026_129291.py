from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.php import cve_2026_129291 as fpm


class _FakeSession:
    def __init__(self, first: str = "ok", second: str = "stderr") -> None:
        self.first = first
        self.second = second
        self.transcript: list[dict] = []

    def get(self, url: str, timeout: int | None = None) -> dict[str, object]:
        if "bg=1" in url:
            if self.first == "fail":
                return {"status": 500, "body": "PHP-CGI-CRASH\n"}
            return {
                "status": 200,
                "body": "ok\n",
                "headers": {"X-Powered-By": ["PHP/8.5.12"]},
            }
        if self.second == "transport":
            return {"status": 0, "error": {"type": "TransportError", "message": "boom"}}
        if self.second == "stderr":
            return {"status": 200, "body": "write to stderr failed"}
        if self.second == "unexpected":
            return {"status": 200, "body": "unexpected\n"}
        return {
            "status": 200,
            "body": "ok\n",
            "headers": {"X-Powered-By": ["PHP/8.5.12"]},
        }


def _probe(fake: _FakeSession):
    with patch.object(fpm, "HttpSession", return_value=fake), patch.object(fpm.time, "sleep"):
        return fpm.run_aggressive_probe("http://127.0.0.1:9111")


def test_129291_classify_boundaries():
    assert fpm.classify_version("8.1.19") == "NOT_AFFECTED"
    assert fpm.classify_version("8.1.20") == "NOT_CONFIRMED"
    assert fpm.classify_version("8.1.34") == "NOT_CONFIRMED"
    assert fpm.classify_version("8.1.35") == "NOT_AFFECTED"
    assert fpm.classify_version("8.2.6") == "NOT_AFFECTED"
    assert fpm.classify_version("8.2.7") == "LIKELY_VULNERABLE"
    assert fpm.classify_version("8.2.35") == "LIKELY_VULNERABLE"
    assert fpm.classify_version("8.2.36") == "PATCHED"
    assert fpm.classify_version("8.3.36") == "LIKELY_VULNERABLE"
    assert fpm.classify_version("8.3.37") == "PATCHED"
    assert fpm.classify_version("8.4.27") == "LIKELY_VULNERABLE"
    assert fpm.classify_version("8.4.28") == "PATCHED"
    assert fpm.classify_version("8.5.12") == "LIKELY_VULNERABLE"
    assert fpm.classify_version("8.5.13") == "PATCHED"
    assert fpm.classify_version("8.0.30") == "NOT_AFFECTED"
    assert fpm.classify_version("8.6.0") == "NOT_AFFECTED"
    assert fpm.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_129291_passive_results():
    vulnerable = fpm.passive_result({"detected": True, "version": "8.5.12"})
    assert vulnerable.status == "LIKELY_VULNERABLE"
    assert "catch_workers_output" in vulnerable.detail

    patched = fpm.passive_result({"detected": True, "version": "8.5.13"})
    assert patched.status == "PATCHED"

    eol = fpm.passive_result({"detected": True, "version": "8.1.25"})
    assert eol.status == "NOT_CONFIRMED"
    assert "8.1.20-8.1.34" in eol.detail

    unaffected = fpm.passive_result({"detected": True, "version": "8.2.6"})
    assert unaffected.status == "NOT_AFFECTED"

    missing = fpm.passive_result({"detected": False})
    assert missing.status == "NOT_DETECTED"


def test_129291_stderr_failure_confirms():
    fake = _FakeSession(second="stderr")
    result = _probe(fake)
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["stderr_write_failed"] is True
    assert result.evidence["lab_php"] == "8.5.12"


def test_129291_second_ok_is_not_confirmed():
    fake = _FakeSession(second="ok")
    result = _probe(fake)
    assert result.status == "NOT_CONFIRMED"
    assert result.confidence == "HIGH"


def test_129291_first_failure_is_not_confirmed():
    fake = _FakeSession(first="fail")
    result = _probe(fake)
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["first_status"] == 500


def test_129291_second_transport_is_error():
    fake = _FakeSession(second="transport")
    result = _probe(fake)
    assert result.status == "ERROR"
    assert result.confidence == "LOW"


def test_129291_unexpected_second_is_not_confirmed():
    fake = _FakeSession(second="unexpected")
    result = _probe(fake)
    assert result.status == "NOT_CONFIRMED"
    assert result.confidence == "MEDIUM"


def test_129291_check_aggressive_only_and_version_gate():
    with patch.object(fpm, "HttpSession", return_value=_FakeSession()), patch.object(fpm.time, "sleep"):
        safe = fpm.check(
            "http://127.0.0.1:9111",
            php_runtime={"detected": True, "version": "8.5.12"},
            run_exploit_check=True,
            exploit_mode="safe",
        )
    assert safe.status == "LIKELY_VULNERABLE"
    assert "aggressive mode" in safe.detail

    with patch.object(fpm, "HttpSession", return_value=_FakeSession()), patch.object(fpm.time, "sleep"):
        aggressive = fpm.check(
            "http://127.0.0.1:9111",
            php_runtime={"detected": True, "version": "8.5.12"},
            run_exploit_check=True,
            exploit_mode="aggressive",
        )
    assert aggressive.status == "VULNERABLE"

    patched = fpm.check(
        "http://127.0.0.1:9111",
        php_runtime={"detected": True, "version": "8.5.13"},
        run_exploit_check=True,
        exploit_mode="aggressive",
    )
    assert patched.status == "PATCHED"


def test_129291_metadata_contract():
    meta = fpm.metadata()
    assert meta["cve"] == "CVE-2026-129291"
    assert meta["cms"] == "php"
    assert meta["exploit_modes"] == ["aggressive"]
    assert meta["vulnerability_type"] == "Privilege Escalation"
    assert "8.5.13" in meta["affected_rule"]
