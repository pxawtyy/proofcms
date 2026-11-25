from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_126045 as lfi


class FakeClient:
    def __init__(self, body: str = "", status: int = 200, error: bool = False) -> None:
        self.body = body
        self.status = status
        self.error = error
        self.urls: list[str] = []

    def get(self, url: str, timeout: int | None = None) -> dict:
        self.urls.append(url)
        if self.error:
            return {"status": 0, "body": "", "error": {"type": "TransportError", "message": "boom"}}
        return {"status": self.status, "body": self.body}


def test_126045_version_boundaries():
    assert lfi.classify_version("1.5.0") == "NOT_AFFECTED"
    assert lfi.classify_version("1.6.0") == "LIKELY_VULNERABLE"
    assert lfi.classify_version("3.10.12") == "LIKELY_VULNERABLE"
    assert lfi.classify_version("5.4.10") == "LIKELY_VULNERABLE"
    assert lfi.classify_version("5.4.11") == "PATCHED"
    assert lfi.classify_version("6.0.0") == "LIKELY_VULNERABLE"
    assert lfi.classify_version("6.2.0") == "LIKELY_VULNERABLE"
    assert lfi.classify_version("6.2.1") == "PATCHED"
    assert lfi.classify_version(None) == "INCONCLUSIVE"


def test_126045_passive_result():
    vulnerable = lfi.check("https://target.test", joomla_version="5.4.10")
    assert vulnerable.status == "LIKELY_VULNERABLE"
    assert vulnerable.exploit_available is True
    assert "5.4.11" in vulnerable.action

    patched = lfi.check("https://target.test", joomla_version="5.4.11")
    assert patched.status == "PATCHED"


def test_126045_safe_probe_confirms_marker():
    fake = FakeClient(body="<input placeholder='PROOFCMS_LFI_MARKER'>")
    with patch.object(lfi, "HttpClient", return_value=fake):
        result = lfi.run_safe_probe(
            "https://target.test",
            "../../../../tmp/proofcms-lfi",
            "PROOFCMS_LFI_MARKER",
            timeout=1,
        )
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["marker_found"] is True
    assert "../../../../tmp/proofcms-lfi" in fake.urls[0]


def test_126045_patched_control_does_not_confirm():
    fake = FakeClient(body="<input placeholder='Password'>")
    with patch.object(lfi, "HttpClient", return_value=fake):
        result = lfi.run_safe_probe(
            "https://target.test",
            "../../../../tmp/proofcms-lfi",
            "PROOFCMS_LFI_MARKER",
            timeout=1,
        )
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["marker_found"] is False


def test_126045_transport_error():
    fake = FakeClient(error=True)
    with patch.object(lfi, "HttpClient", return_value=fake):
        result = lfi.run_safe_probe("https://target.test", "x", "marker", timeout=1)
    assert result.status == "ERROR"
    assert result.confidence == "LOW"


def test_126045_check_needs_lab_marker():
    result = lfi.check(
        "https://target.test",
        joomla_version="5.4.10",
        run_exploit_check=True,
        exploit_mode="safe",
    )
    assert result.status == "BLOCKED_EXTERNAL"
    assert result.exploit_ran is False
    assert "language=" in result.detail


def test_126045_check_passes_lab_args():
    with patch.object(lfi, "run_safe_probe", return_value=lfi.check("https://target.test")) as probe:
        lfi.check(
            "https://target.test",
            joomla_version="5.4.10",
            run_exploit_check=True,
            exploit_mode="safe",
            aggressive_args={"language": "../../../../tmp/proofcms-lfi", "marker": "M"},
        )
        probe.assert_called_once()
        assert probe.call_args.args[1] == "../../../../tmp/proofcms-lfi"
        assert probe.call_args.args[2] == "M"


def test_126045_metadata_contract():
    meta = lfi.metadata()
    assert meta["cve"] == "CVE-2026-126045"
    assert meta["exploit_modes"] == ["safe"]
    assert meta["intrusive"] is False
    assert meta["affected_joomla_versions"] == ["1.6.0-5.4.10", "6.0.0-6.2.0"]
