from proofcms.modules.joomla import cve_2026_48908, cve_2026_56291, cve_2026_57827


def _plugin(name: str, version: str) -> dict[str, dict[str, object]]:
    return {name: {"found": True, "version": version}}


def test_fresh_sp_page_builder_610_is_patched():
    result = cve_2026_48908.passive_result(_plugin("sppagebuilder", "6.10.0"))
    assert result.status == "PATCHED"
    assert cve_2026_48908.passive_result(_plugin("sppagebuilder", "3.8.9")).status == "LIKELY_VULNERABLE"


def test_fresh_balbooa_2440_is_patched():
    result = cve_2026_56291.passive_result(_plugin("baforms", "2.4.4.0"))
    assert result.status == "PATCHED"
    assert cve_2026_56291.passive_result(_plugin("baforms", "2.4.0")).status == "LIKELY_VULNERABLE"


def test_fresh_rsfiles_11629_remains_in_affected_range():
    result = cve_2026_57827.passive_result(_plugin("rsfiles", "1.16.29"))
    assert result.status == "LIKELY_VULNERABLE"
    assert cve_2026_57827.passive_result(_plugin("rsfiles", "1.17.12")).status == "PATCHED"
