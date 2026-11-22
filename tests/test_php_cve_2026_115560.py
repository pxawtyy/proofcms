from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.php import cve_2026_115560 as ser


class _FakeClient:
    def __init__(self, write: str = "ok", read: str = "fired") -> None:
        self.write = write
        self.read = read
        self.transcript: list[dict] = []

    def post_multipart(
        self,
        url: str,
        fields: dict | None = None,
        files: dict | None = None,
        headers: dict | None = None,
        timeout: int | None = None,
    ) -> dict[str, object]:
        if self.write == "transport":
            return {"status": 0, "error": {"type": "TransportError", "message": "boom"}}
        if self.write == "fail":
            return {"status": 500, "body": "PHP-CGI-CRASH\n"}
        return {"status": 200, "body": "WRITE_OK\n"}

    def get(
        self,
        url: str,
        headers: dict | None = None,
        timeout: int | None = None,
    ) -> dict[str, object]:
        if self.read == "transport":
            return {"status": 0, "error": {"type": "TransportError", "message": "boom"}}
        body = "GADGET_FIRED\n" if self.read == "fired" else "GADGET_NOT_FIRED\n"
        return {
            "status": 200,
            "body": body,
            "headers": {"X-Powered-By": ["PHP/8.5.12"]},
        }


def test_115560_classify_branches():
    assert ser.classify_version("8.5.12") == "LIKELY_VULNERABLE"
    assert ser.classify_version("8.5.13") == "PATCHED"
    assert ser.classify_version("8.4.27") == "LIKELY_VULNERABLE"
    assert ser.classify_version("8.4.28") == "PATCHED"
    assert ser.classify_version("8.3.36") == "LIKELY_VULNERABLE"
    assert ser.classify_version("8.3.37") == "PATCHED"
    assert ser.classify_version("8.2.35") == "LIKELY_VULNERABLE"
    assert ser.classify_version("8.2.36") == "PATCHED"
    assert ser.classify_version("8.1.0") == "NOT_CONFIRMED"
    assert ser.classify_version("8.6.0") == "NOT_AFFECTED"
    assert ser.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_115560_passive_results():
    vulnerable = ser.passive_result({"detected": True, "version": "8.5.12"})
    assert vulnerable.status == "LIKELY_VULNERABLE"
    assert "upload_progress" in vulnerable.detail
    assert "php_serialize" in vulnerable.detail

    patched = ser.passive_result({"detected": True, "version": "8.5.13"})
    assert patched.status == "PATCHED"

    legacy = ser.passive_result({"detected": True, "version": "8.1.0"})
    assert legacy.status == "NOT_CONFIRMED"

    unaffected = ser.passive_result({"detected": True, "version": "8.6.0"})
    assert unaffected.status == "NOT_AFFECTED"

    missing = ser.passive_result({"detected": False})
    assert missing.status == "NOT_DETECTED"


def test_115560_gadget_fired_confirms():
    fake = _FakeClient(read="fired")
    with patch.object(ser, "HttpClient", return_value=fake):
        result = ser.run_aggressive_probe("http://127.0.0.1:9109")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["gadget_fired"] is True
    assert result.evidence["gadget_not_fired"] is False
    assert result.evidence["lab_php"] == "8.5.12"


def test_115560_not_fired_is_not_confirmed():
    fake = _FakeClient(read="not")
    with patch.object(ser, "HttpClient", return_value=fake):
        result = ser.run_aggressive_probe("http://127.0.0.1:9109")
    assert result.status == "NOT_CONFIRMED"
    assert result.confidence == "HIGH"
    assert result.evidence["gadget_not_fired"] is True


def test_115560_write_failure_is_not_confirmed():
    fake = _FakeClient(write="fail")
    with patch.object(ser, "HttpClient", return_value=fake):
        result = ser.run_aggressive_probe("http://127.0.0.1:9109")
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["write_status"] == 500


def test_115560_write_transport_is_not_confirmed():
    fake = _FakeClient(write="transport")
    with patch.object(ser, "HttpClient", return_value=fake):
        result = ser.run_aggressive_probe("http://127.0.0.1:9109")
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["write_transport_error"] is True


def test_115560_read_transport_is_error():
    fake = _FakeClient(read="transport")
    with patch.object(ser, "HttpClient", return_value=fake):
        result = ser.run_aggressive_probe("http://127.0.0.1:9109")
    assert result.status == "ERROR"
    assert result.confidence == "LOW"


def test_115560_check_aggressive_only_and_version_gate():
    with patch.object(ser, "HttpClient", return_value=_FakeClient()):
        safe = ser.check(
            "http://127.0.0.1:9109",
            php_runtime={"detected": True, "version": "8.5.12"},
            run_exploit_check=True,
            exploit_mode="safe",
        )
    assert safe.status == "LIKELY_VULNERABLE"
    assert "aggressive mode" in safe.detail

    with patch.object(ser, "HttpClient", return_value=_FakeClient()):
        aggressive = ser.check(
            "http://127.0.0.1:9109",
            php_runtime={"detected": True, "version": "8.5.12"},
            run_exploit_check=True,
            exploit_mode="aggressive",
        )
    assert aggressive.status == "VULNERABLE"

    patched = ser.check(
        "http://127.0.0.1:9109",
        php_runtime={"detected": True, "version": "8.5.13"},
        run_exploit_check=True,
        exploit_mode="aggressive",
    )
    assert patched.status == "PATCHED"


def test_115560_metadata_contract():
    meta = ser.metadata()
    assert meta["cve"] == "CVE-2026-115560"
    assert meta["cms"] == "php"
    assert meta["exploit_modes"] == ["aggressive"]
    assert meta["vulnerability_type"] == "Object Injection"
    assert "8.5.13" in meta["affected_rule"]
