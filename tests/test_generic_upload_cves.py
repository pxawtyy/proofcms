from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.generic import cve_2018_9206, cve_2021_23394, cve_2026_81891
from proofcms.modules.wordpress import cve_2024_6220


def test_new_version_boundaries():
    assert cve_2018_9206.classify_version("9.22.0") == "LIKELY_VULNERABLE"
    assert cve_2018_9206.classify_version("9.22.1") == "PATCHED"
    assert cve_2021_23394.classify_version("2.1.57") == "LIKELY_VULNERABLE"
    assert cve_2021_23394.classify_version("2.1.58") == "PATCHED"
    assert cve_2026_81891.classify_version("2.1.69") == "LIKELY_VULNERABLE"
    assert cve_2026_81891.classify_version("2.1.70") == "PATCHED"
    assert cve_2024_6220.classify_version("2.5.2") == "LIKELY_VULNERABLE"
    assert cve_2024_6220.classify_version("2.5.3") == "PATCHED"


def test_phar_inert_upload_confirmation():
    conn = {"version": "2.1.57", "endpoint": "/elfinder/php/connector.php", "target": "root"}
    with (
        patch("proofcms.modules.generic.cve_2021_23394.discover", return_value=conn),
        patch("proofcms.modules.generic.cve_2021_23394.upload", return_value={"added": [{"name": "ignored"}]}),
        patch("proofcms.modules.generic.cve_2021_23394.first_added", return_value={"hash": "filehash"}),
        patch("proofcms.modules.generic.cve_2021_23394.read_file", return_value="PROOFCMS_SAFE_MARK"),
        patch("proofcms.modules.generic.cve_2021_23394.cleanup"),
        patch("proofcms.modules.generic.cve_2021_23394.endpoint_url", return_value="https://test/connector"),
        patch("proofcms.modules.generic.cve_2021_23394.secrets.token_hex", side_effect=["MARK", "FILE"]),
    ):
        result = cve_2021_23394.check("https://test", run_exploit_check=True)
    assert result.status == "VULNERABLE_UPLOAD_ONLY"
    assert result.exploit_ran


def test_archive_bypass_requires_rejected_direct_control():
    conn = {"version": "2.1.69", "endpoint": "/elfinder/php/connector.php", "target": "root"}
    with (
        patch("proofcms.modules.generic.cve_2026_81891.discover", return_value=conn),
        patch("proofcms.modules.generic.cve_2026_81891.upload", return_value={"added": [{"hash": "direct"}]}),
        patch("proofcms.modules.generic.cve_2026_81891.first_added", return_value={"hash": "direct"}),
        patch("proofcms.modules.generic.cve_2026_81891.cleanup"),
        patch("proofcms.modules.generic.cve_2026_81891.endpoint_url", return_value="https://test/connector"),
    ):
        result = cve_2026_81891.check("https://test", run_exploit_check=True)
    assert result.status == "NOT_CONFIRMED"
    assert "direct" in result.detail.lower()


def test_keydatas_passive_detection():
    result = cve_2024_6220.check(
        "https://test",
        plugins={"keydatas": {"found": True, "version": "2.5.2", "source": "readme.txt"}},
    )
    assert result.status == "LIKELY_VULNERABLE"
