from __future__ import annotations

from proofcms.modules.joomla import cve_2014_7984, cve_2020_13763, cve_2020_35616


def test_35616_version_gates():
    assert cve_2020_35616.classify_version("1.6.5") == "NOT_AFFECTED"
    assert cve_2020_35616.classify_version("1.7.0") == "LIKELY_VULNERABLE"
    assert cve_2020_35616.classify_version("3.9.22") == "LIKELY_VULNERABLE"
    assert cve_2020_35616.classify_version("3.9.23") == "PATCHED"
    assert cve_2020_35616.classify_version("5.0.0") == "PATCHED"
    assert cve_2020_35616.classify_version(None) == "INCONCLUSIVE"


def test_7984_version_gates():
    assert cve_2014_7984.classify_version("1.7.3") == "NOT_AFFECTED"
    assert cve_2014_7984.classify_version("2.5.18") == "LIKELY_VULNERABLE"
    assert cve_2014_7984.classify_version("2.5.19") == "PATCHED"
    assert cve_2014_7984.classify_version("3.0.0") == "LIKELY_VULNERABLE"
    assert cve_2014_7984.classify_version("3.2.2") == "LIKELY_VULNERABLE"
    assert cve_2014_7984.classify_version("3.2.3") == "PATCHED"
    assert cve_2014_7984.classify_version("4.0.0") == "PATCHED"
    assert cve_2014_7984.classify_version(None) == "INCONCLUSIVE"


def test_passive_core_checks_have_no_active_proof():
    for module, version in ((cve_2020_35616, "3.9.22"), (cve_2014_7984, "3.2.2")):
        result = module.check(
            "https://fixture.test", joomla_version=version, run_exploit_check=True
        )
        assert result.status == "LIKELY_VULNERABLE"
        assert result.exploit_available is False
        assert result.exploit_ran is False
        assert "version-based assessment only" in result.detail


def test_13763_version_gates():
    assert cve_2020_13763.classify_version("2.4.0") == "NOT_AFFECTED"
    assert cve_2020_13763.classify_version("2.5.0") == "LIKELY_VULNERABLE"
    assert cve_2020_13763.classify_version("3.9.18") == "LIKELY_VULNERABLE"
    assert cve_2020_13763.classify_version("3.9.19") == "PATCHED"
    assert cve_2020_13763.classify_version("4.0.0") == "PATCHED"
    assert cve_2020_13763.classify_version(None) == "INCONCLUSIVE"


def test_13763_passive_check():
    result = cve_2020_13763.check(
        "https://fixture.test", joomla_version="3.9.18", run_exploit_check=True
    )
    assert result.status == "LIKELY_VULNERABLE"
    assert result.exploit_available is False
    assert result.exploit_ran is False
    assert "version-based assessment only" in result.detail


def test_metadata_types():
    assert cve_2020_35616.metadata()["vulnerability_type"] == "Improper Access Control"
    assert cve_2020_13763.metadata()["vulnerability_type"] == "Cross-Site Scripting (XSS)"
    assert cve_2014_7984.metadata()["vulnerability_type"] == "Authentication Bypass"
