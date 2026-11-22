from __future__ import annotations

from proofcms.modules.joomla import cve_2018_15881, cve_2019_10945


def test_15881_version_gates():
    assert cve_2018_15881.classify_version("3.6.5") == "NOT_AFFECTED"
    assert cve_2018_15881.classify_version("3.7.0") == "LIKELY_VULNERABLE"
    assert cve_2018_15881.classify_version("3.8.11") == "LIKELY_VULNERABLE"
    assert cve_2018_15881.classify_version("3.8.12") == "PATCHED"
    assert cve_2018_15881.classify_version("4.0.0") == "PATCHED"
    assert cve_2018_15881.classify_version(None) == "INCONCLUSIVE"


def test_10945_version_gates():
    assert cve_2019_10945.classify_version("1.4.2") == "NOT_AFFECTED"
    assert cve_2019_10945.classify_version("1.5.0") == "LIKELY_VULNERABLE"
    assert cve_2019_10945.classify_version("3.9.4") == "LIKELY_VULNERABLE"
    assert cve_2019_10945.classify_version("3.9.5") == "PATCHED"
    assert cve_2019_10945.classify_version("4.0.0") == "PATCHED"
    assert cve_2019_10945.classify_version(None) == "INCONCLUSIVE"


def test_passive_core_check_has_no_active_proof():
    result = cve_2018_15881.check(
        "https://fixture.test", joomla_version="3.8.11", run_exploit_check=True
    )
    assert result.status == "LIKELY_VULNERABLE"
    assert result.exploit_available is False
    assert result.exploit_ran is False
    assert "version-based assessment only" in result.detail


def test_10945_probe_requires_supplied_account_and_sentinel():
    result = cve_2019_10945.check(
        "https://fixture.test", joomla_version="3.9.4", run_exploit_check=True
    )
    assert result.status == "NOT_CONFIRMED"
    assert result.exploit_available is True
    assert result.exploit_ran is False
    assert "admin_user" in result.detail


def test_10945_probe_rejects_reflection_risk():
    result = cve_2019_10945.run_safe_probe(
        "https://fixture.test",
        aggressive_args={
            "admin_user": "tester",
            "admin_password": "pw",
            "sentinel_file": "marker.txt",
            "sentinel_folder": "../marker.txt",
        },
    )
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["rejected_reflection_risk"] is True


def test_10945_safe_probe_readonly_differential():
    from unittest.mock import patch

    baseline = {"status": 200, "body": '<li data-name="logo.png"></li>'}
    probe = {
        "status": 200,
        "body": '<li data-name="logo.png"></li><li data-name="proofcms-marker.txt"></li>',
    }
    with patch.object(cve_2019_10945, "joomla_admin_login", return_value=True), patch.object(
        cve_2019_10945.HttpClient, "get", side_effect=[baseline, probe]
    ):
        result = cve_2019_10945.run_safe_probe(
            "https://fixture.test",
            aggressive_args={
                "admin_user": "tester",
                "admin_password": "pw",
                "sentinel_file": "proofcms-marker.txt",
                "sentinel_folder": "../proofcms-sentinel",
            },
        )
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["sentinel_enumerated"] is True
    assert result.evidence["sentinel_in_baseline"] is False


def test_10945_safe_probe_not_confirmed_when_sentinel_absent():
    from unittest.mock import patch

    response = {"status": 200, "body": '<li data-name="logo.png"></li>'}
    with patch.object(cve_2019_10945, "joomla_admin_login", return_value=True), patch.object(
        cve_2019_10945.HttpClient, "get", return_value=response
    ):
        result = cve_2019_10945.run_safe_probe(
            "https://fixture.test",
            aggressive_args={
                "admin_user": "tester",
                "admin_password": "pw",
                "sentinel_file": "proofcms-marker.txt",
            },
        )
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["sentinel_enumerated"] is False


def test_metadata_types():
    assert cve_2018_15881.metadata()["vulnerability_type"] == "Improper Access Control"
    assert cve_2019_10945.metadata()["vulnerability_type"] == "Path Traversal"
