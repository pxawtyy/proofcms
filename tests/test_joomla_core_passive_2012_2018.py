from __future__ import annotations

from proofcms.modules.joomla import cve_2012_1563, cve_2018_11323


def test_1563_version_gates():
    assert cve_2012_1563.classify_version("1.5.2") == "NOT_AFFECTED"
    assert cve_2012_1563.classify_version("1.6.0") == "LIKELY_VULNERABLE"
    assert cve_2012_1563.classify_version("1.7.5") == "LIKELY_VULNERABLE"
    assert cve_2012_1563.classify_version("2.4.0") == "NOT_AFFECTED"
    assert cve_2012_1563.classify_version("2.5.0") == "LIKELY_VULNERABLE"
    assert cve_2012_1563.classify_version("2.5.2") == "LIKELY_VULNERABLE"
    assert cve_2012_1563.classify_version("2.5.3") == "PATCHED"
    assert cve_2012_1563.classify_version("3.0.0") == "PATCHED"
    assert cve_2012_1563.classify_version(None) == "INCONCLUSIVE"


def test_11323_version_gates():
    assert cve_2018_11323.classify_version("2.4.0") == "NOT_AFFECTED"
    assert cve_2018_11323.classify_version("2.5.0") == "LIKELY_VULNERABLE"
    assert cve_2018_11323.classify_version("3.8.7") == "LIKELY_VULNERABLE"
    assert cve_2018_11323.classify_version("3.8.8") == "PATCHED"
    assert cve_2018_11323.classify_version("4.0.0") == "PATCHED"
    assert cve_2018_11323.classify_version(None) == "INCONCLUSIVE"


def test_passive_core_checks_have_no_active_proof():
    for module, version in ((cve_2012_1563, "2.5.2"), (cve_2018_11323, "3.8.7")):
        result = module.check(
            "https://fixture.test", joomla_version=version, run_exploit_check=True
        )
        assert result.status == "LIKELY_VULNERABLE"
        assert result.exploit_available is False
        assert result.exploit_ran is False
        assert "version-based assessment only" in result.detail


def test_metadata_types():
    assert cve_2012_1563.metadata()["vulnerability_type"] == "Privilege Escalation"
    assert cve_2018_11323.metadata()["vulnerability_type"] == "Improper Access Control"
