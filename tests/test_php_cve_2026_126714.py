from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.php import cve_2026_126714 as sess


class _FakeSession:
    def __init__(
        self,
        baseline: bool = True,
        probe: str = "present",
    ) -> None:
        self.baseline = baseline
        self.probe = probe
        self.transcript: list[dict] = []

    def get(self, url: str, timeout: int | None = None) -> dict[str, object]:
        if "phase=2" in url:
            if self.probe == "transport":
                return {"status": 0, "error": {"type": "TransportError", "message": "boom"}}
            if self.probe == "present":
                return {"status": 200, "body": "OLD_SUFFIX_PRESENT\n"}
            if self.probe == "absent":
                return {"status": 200, "body": "OLD_SUFFIX_ABSENT\n"}
            return {"status": 200, "body": "unexpected\n"}
        if not self.baseline:
            return {"status": 404, "body": "Not Found"}
        return {
            "status": 200,
            "body": "OLD_WRITTEN\n",
            "headers": {"X-Powered-By": ["PHP/8.5.12"]},
        }


def test_126714_classify_branches():
    assert sess.classify_version("8.5.12") == "LIKELY_VULNERABLE"
    assert sess.classify_version("8.5.13") == "PATCHED"
    assert sess.classify_version("8.4.27") == "LIKELY_VULNERABLE"
    assert sess.classify_version("8.4.28") == "PATCHED"
    assert sess.classify_version("8.3.36") == "LIKELY_VULNERABLE"
    assert sess.classify_version("8.3.37") == "PATCHED"
    assert sess.classify_version("8.2.35") == "LIKELY_VULNERABLE"
    assert sess.classify_version("8.2.36") == "PATCHED"
    assert sess.classify_version("8.1.0") == "NOT_CONFIRMED"
    assert sess.classify_version("8.6.0") == "NOT_AFFECTED"
    assert sess.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_126714_passive_results():
    vulnerable = sess.passive_result({"detected": True, "version": "8.5.12"})
    assert vulnerable.status == "LIKELY_VULNERABLE"
    assert "files session handler" in vulnerable.detail
    assert "upload progress" in vulnerable.detail

    patched = sess.passive_result({"detected": True, "version": "8.5.13"})
    assert patched.status == "PATCHED"

    legacy = sess.passive_result({"detected": True, "version": "8.1.0"})
    assert legacy.status == "NOT_CONFIRMED"
    assert legacy.evidence["package_backport_required"] is True

    unaffected = sess.passive_result({"detected": True, "version": "8.6.0"})
    assert unaffected.status == "NOT_AFFECTED"

    missing = sess.passive_result({"detected": False})
    assert missing.status == "NOT_DETECTED"


def test_126714_present_suffix_confirms():
    fake = _FakeSession(probe="present")
    with patch.object(sess, "HttpSession", return_value=fake):
        result = sess.run_aggressive_probe("http://127.0.0.1:9107")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["old_suffix_present"] is True
    assert result.evidence["old_suffix_absent"] is False
    assert result.evidence["lab_php"] == "8.5.12"


def test_126714_absent_suffix_is_not_confirmed():
    fake = _FakeSession(probe="absent")
    with patch.object(sess, "HttpSession", return_value=fake):
        result = sess.run_aggressive_probe("http://127.0.0.1:9107")
    assert result.status == "NOT_CONFIRMED"
    assert result.confidence == "HIGH"
    assert result.evidence["old_suffix_absent"] is True


def test_126714_missing_lab_app_is_not_confirmed():
    fake = _FakeSession(baseline=False)
    with patch.object(sess, "HttpSession", return_value=fake):
        result = sess.run_aggressive_probe("http://127.0.0.1:9107")
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["baseline_status"] == 404


def test_126714_transport_probe_is_error():
    fake = _FakeSession(probe="transport")
    with patch.object(sess, "HttpSession", return_value=fake):
        result = sess.run_aggressive_probe("http://127.0.0.1:9107")
    assert result.status == "ERROR"
    assert result.confidence == "LOW"


def test_126714_unexpected_probe_is_not_confirmed():
    fake = _FakeSession(probe="unexpected")
    with patch.object(sess, "HttpSession", return_value=fake):
        result = sess.run_aggressive_probe("http://127.0.0.1:9107")
    assert result.status == "NOT_CONFIRMED"
    assert result.confidence == "MEDIUM"


def test_126714_check_aggressive_only_and_version_gate():
    with patch.object(sess, "HttpSession", return_value=_FakeSession()):
        safe = sess.check(
            "http://127.0.0.1:9107",
            php_runtime={"detected": True, "version": "8.5.12"},
            run_exploit_check=True,
            exploit_mode="safe",
        )
    assert safe.status == "LIKELY_VULNERABLE"
    assert "aggressive mode" in safe.detail

    with patch.object(sess, "HttpSession", return_value=_FakeSession()):
        aggressive = sess.check(
            "http://127.0.0.1:9107",
            php_runtime={"detected": True, "version": "8.5.12"},
            run_exploit_check=True,
            exploit_mode="aggressive",
        )
    assert aggressive.status == "VULNERABLE"

    patched = sess.check(
        "http://127.0.0.1:9107",
        php_runtime={"detected": True, "version": "8.5.13"},
        run_exploit_check=True,
        exploit_mode="aggressive",
    )
    assert patched.status == "PATCHED"


def test_126714_metadata_contract():
    meta = sess.metadata()
    assert meta["cve"] == "CVE-2026-126714"
    assert meta["cms"] == "php"
    assert meta["exploit_modes"] == ["aggressive"]
    assert meta["vulnerability_type"] == "Object Injection"
    assert "8.5.13" in meta["affected_rule"]
