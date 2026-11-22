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


def test_passive_core_checks_have_no_active_proof():
    for module, version in ((cve_2018_15881, "3.8.11"), (cve_2019_10945, "3.9.4")):
        result = module.check(
            "https://fixture.test", joomla_version=version, run_exploit_check=True
        )
        assert result.status == "LIKELY_VULNERABLE"
        assert result.exploit_available is False
        assert result.exploit_ran is False
        assert "version-based assessment only" in result.detail


def test_metadata_types():
    assert cve_2018_15881.metadata()["vulnerability_type"] == "Improper Access Control"
    assert cve_2019_10945.metadata()["vulnerability_type"] == "Path Traversal"
