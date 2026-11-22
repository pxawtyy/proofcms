from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.php import cve_2026_128090 as phar


class _FakeClient:
    def __init__(self, mode: str = "bypass") -> None:
        self.mode = mode
        self.transcript: list[dict] = []

    def get(self, url: str, headers=None, timeout: int | None = None) -> dict[str, object]:
        if self.mode == "transport":
            return {"status": 0, "error": {"type": "TransportError", "message": "boom"}}
        if self.mode == "rejected":
            body = (
                'REJECTED phar "/tmp/lab.phar" SHA256 signature could not be verified: '
                "openssl public key found, but the signature does not use openssl\n"
            )
        elif self.mode == "unexpected":
            body = "something else\n"
        else:
            body = "BYPASS hash_type=SHA-256 output=PWNED\n"
        return {
            "status": 200,
            "body": body,
            "headers": {"X-Powered-By": ["PHP/8.5.12"]},
        }


def test_128090_classify_branches():
    assert phar.classify_version("8.5.12") == "LIKELY_VULNERABLE"
    assert phar.classify_version("8.5.13") == "PATCHED"
    assert phar.classify_version("8.4.27") == "LIKELY_VULNERABLE"
    assert phar.classify_version("8.4.28") == "PATCHED"
    assert phar.classify_version("8.3.36") == "LIKELY_VULNERABLE"
    assert phar.classify_version("8.3.37") == "PATCHED"
    assert phar.classify_version("8.2.35") == "LIKELY_VULNERABLE"
    assert phar.classify_version("8.2.36") == "PATCHED"
    assert phar.classify_version("8.1.0") == "NOT_CONFIRMED"
    assert phar.classify_version("8.6.0") == "NOT_AFFECTED"
    assert phar.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_128090_passive_results():
    vulnerable = phar.passive_result({"detected": True, "version": "8.5.12"})
    assert vulnerable.status == "LIKELY_VULNERABLE"
    assert ".pubkey" in vulnerable.detail
    assert "SHA-256" in vulnerable.detail

    patched = phar.passive_result({"detected": True, "version": "8.5.13"})
    assert patched.status == "PATCHED"

    legacy = phar.passive_result({"detected": True, "version": "8.1.0"})
    assert legacy.status == "NOT_CONFIRMED"

    unaffected = phar.passive_result({"detected": True, "version": "8.6.0"})
    assert unaffected.status == "NOT_AFFECTED"

    missing = phar.passive_result({"detected": False})
    assert missing.status == "NOT_DETECTED"


def test_128090_bypass_confirms():
    with patch.object(phar, "HttpClient", return_value=_FakeClient("bypass")):
        result = phar.run_aggressive_probe("http://127.0.0.1:9113")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["bypass"] is True
    assert result.evidence["lab_php"] == "8.5.12"


def test_128090_rejected_is_not_confirmed():
    with patch.object(phar, "HttpClient", return_value=_FakeClient("rejected")):
        result = phar.run_aggressive_probe("http://127.0.0.1:9113")
    assert result.status == "NOT_CONFIRMED"
    assert result.confidence == "HIGH"
    assert result.evidence["rejected"] is True


def test_128090_transport_is_error():
    with patch.object(phar, "HttpClient", return_value=_FakeClient("transport")):
        result = phar.run_aggressive_probe("http://127.0.0.1:9113")
    assert result.status == "ERROR"
    assert result.confidence == "LOW"


def test_128090_unexpected_is_not_confirmed():
    with patch.object(phar, "HttpClient", return_value=_FakeClient("unexpected")):
        result = phar.run_aggressive_probe("http://127.0.0.1:9113")
    assert result.status == "NOT_CONFIRMED"
    assert result.confidence == "MEDIUM"


def test_128090_check_aggressive_only_and_version_gate():
    with patch.object(phar, "HttpClient", return_value=_FakeClient("bypass")):
        safe = phar.check(
            "http://127.0.0.1:9113",
            php_runtime={"detected": True, "version": "8.5.12"},
            run_exploit_check=True,
            exploit_mode="safe",
        )
    assert safe.status == "LIKELY_VULNERABLE"
    assert "aggressive mode" in safe.detail

    with patch.object(phar, "HttpClient", return_value=_FakeClient("bypass")):
        aggressive = phar.check(
            "http://127.0.0.1:9113",
            php_runtime={"detected": True, "version": "8.5.12"},
            run_exploit_check=True,
            exploit_mode="aggressive",
        )
    assert aggressive.status == "VULNERABLE"

    patched = phar.check(
        "http://127.0.0.1:9113",
        php_runtime={"detected": True, "version": "8.5.13"},
        run_exploit_check=True,
        exploit_mode="aggressive",
    )
    assert patched.status == "PATCHED"


def test_128090_metadata_contract():
    meta = phar.metadata()
    assert meta["cve"] == "CVE-2026-128090"
    assert meta["cms"] == "php"
    assert meta["exploit_modes"] == ["aggressive"]
    assert meta["vulnerability_type"] == "Remote Code Execution"
    assert "8.5.13" in meta["affected_rule"]
