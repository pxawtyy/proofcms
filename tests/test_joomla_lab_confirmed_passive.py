from __future__ import annotations

from unittest.mock import patch

from proofcms.core.models import Finding
from proofcms.modules.joomla import cve_2026_90901, cve_2026_100750

TARGET = "https://target.test"


class _FakeManifestClient:
    """Return a Joomla extension manifest with a fixed <version> value."""

    def __init__(self, version: str) -> None:
        self.version = version
        self.calls: list[str] = []

    def get(self, url: str, headers=None, timeout=None) -> dict[str, object]:
        self.calls.append(url)
        return {
            "status": 200,
            "body": f"<?xml version='1.0' encoding='utf-8'?><extension><version>{self.version}</version></extension>",
            "headers": {},
            "final_url": url,
        }


def test_easystore_90901_classifier_boundaries():
    assert cve_2026_90901._classify("1.0.0") == "LIKELY_VULNERABLE"
    assert cve_2026_90901._classify("3.0.0") == "LIKELY_VULNERABLE"
    assert cve_2026_90901._classify("3.0.1") == "NOT_AFFECTED"
    assert cve_2026_90901._classify("3.1.0") == "NOT_AFFECTED"
    assert cve_2026_90901._classify(None) == "DETECTED_VERSION_UNKNOWN"


def test_easystore_90901_check_reads_manifest_without_exploit():
    client = _FakeManifestClient("3.0.0")
    with patch.object(cve_2026_90901, "HttpClient", return_value=client):
        result = cve_2026_90901.check(
            TARGET, run_exploit_check=True, exploit_mode="safe"
        )
    assert isinstance(result, Finding)
    assert result.status == "LIKELY_VULNERABLE"
    assert result.component_version == "3.0.0"
    assert result.exploit_ran is False
    assert client.calls[0].endswith("/administrator/components/com_easystore/easystore.xml")


def test_easystore_90901_patched_manifest_is_not_affected():
    with patch.object(cve_2026_90901, "HttpClient", return_value=_FakeManifestClient("3.0.1")):
        result = cve_2026_90901.check(TARGET)
    assert result.status == "NOT_AFFECTED"
    assert result.exploit_ran is False


def test_easystore_90901_passive_result_from_extensions():
    result = cve_2026_90901.passive_result(
        extensions={"com_easystore": {"found": True, "version": "3.0.0"}}
    )
    assert result.status == "LIKELY_VULNERABLE"
    assert result.exploit_ran is False


def test_easystore_90901_metadata_is_safe_only():
    meta = cve_2026_90901.metadata()
    assert meta["exploit_modes"] == ["safe"]
    assert meta["intrusive"] is False


class _NotFoundClient:
    def get(self, url: str, headers=None, timeout=None) -> dict[str, object]:
        return {"status": 404, "body": "Not Found", "headers": {}, "final_url": url}


def test_easystore_90901_manifest_404_is_not_detected():
    with patch.object(cve_2026_90901, "HttpClient", return_value=_NotFoundClient()):
        result = cve_2026_90901.check(TARGET)
    assert result.status == "NOT_DETECTED"


def test_modulesanywhere_100750_manifest_404_is_not_detected():
    with patch.object(cve_2026_100750, "HttpClient", return_value=_NotFoundClient()):
        result = cve_2026_100750.check(TARGET)
    assert result.status == "NOT_DETECTED"


def test_modulesanywhere_100750_classifier_boundaries():
    assert cve_2026_100750._classify("1.5.0") == "LIKELY_VULNERABLE"
    assert cve_2026_100750._classify("9.0.5") == "LIKELY_VULNERABLE"
    assert cve_2026_100750._classify("9.0.4PRO") == "LIKELY_VULNERABLE"
    assert cve_2026_100750._classify("10.0.0") == "NOT_AFFECTED"
    assert cve_2026_100750._classify(None) == "DETECTED_VERSION_UNKNOWN"


def test_modulesanywhere_100750_check_reads_manifest_without_exploit():
    client = _FakeManifestClient("9.0.4PRO")
    with patch.object(cve_2026_100750, "HttpClient", return_value=client):
        result = cve_2026_100750.check(
            TARGET, run_exploit_check=True, exploit_mode="safe"
        )
    assert isinstance(result, Finding)
    assert result.status == "LIKELY_VULNERABLE"
    assert result.component_version == "9.0.4PRO"
    assert result.exploit_ran is False
    assert client.calls[0].endswith("/plugins/system/modulesanywhere/modulesanywhere.xml")


def test_modulesanywhere_100750_patched_manifest_is_not_affected():
    with patch.object(cve_2026_100750, "HttpClient", return_value=_FakeManifestClient("10.0.0")):
        result = cve_2026_100750.check(TARGET)
    assert result.status == "NOT_AFFECTED"
    assert result.exploit_ran is False


def test_modulesanywhere_100750_passive_result_from_extensions():
    result = cve_2026_100750.passive_result(
        extensions={"plg_system_modulesanywhere": {"found": True, "version": "9.0.4PRO"}}
    )
    assert result.status == "LIKELY_VULNERABLE"
    assert result.exploit_ran is False


def test_modulesanywhere_100750_metadata_is_safe_only():
    meta = cve_2026_100750.metadata()
    assert meta["exploit_modes"] == ["safe"]
    assert meta["intrusive"] is False
