from proofcms.core.categories import VulnerabilityType
from proofcms.modules.php import cve_2026_109618, cve_2026_109619


def test_php_109618_branch_boundaries():
    assert cve_2026_109618.classify_version("8.2.34") == "LIKELY_VULNERABLE"
    assert cve_2026_109618.classify_version("8.2.35") == "PATCHED"
    assert cve_2026_109618.classify_version("8.3.35") == "LIKELY_VULNERABLE"
    assert cve_2026_109618.classify_version("8.4.27") == "PATCHED"
    assert cve_2026_109618.classify_version("8.5.12") == "PATCHED"


def test_php_109619_marks_legacy_builds_package_specific():
    assert cve_2026_109619.classify_version("7.4.33") == "NOT_CONFIRMED"
    result = cve_2026_109619.check(
        "https://fixture.test",
        php_runtime={"detected": True, "version": "7.4.33", "source": "/:X-Powered-By"},
    )
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["package_backport_required"] is True
    assert result.evidence["active_probe"] == "not_sent"


def test_php_2026_advisories_are_memory_corruption_and_passive():
    runtime = {"detected": True, "version": "8.4.26", "source": "/:X-Powered-By"}
    for module in (cve_2026_109618, cve_2026_109619):
        result = module.check("https://fixture.test", php_runtime=runtime)
        assert result.status == "LIKELY_VULNERABLE"
        assert result.vulnerability_type == VulnerabilityType.MEMORY_CORRUPTION
        assert result.exploit_ran is False

