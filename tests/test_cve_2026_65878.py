from __future__ import annotations

from proofcms.modules.joomla import cve_2026_65878


def test_version_classification() -> None:
    assert cve_2026_65878.classify_version("0.9.9") == "NOT_AFFECTED"
    assert cve_2026_65878.classify_version("1.0.0") == "LIKELY_VULNERABLE"
    assert cve_2026_65878.classify_version("6.0.0") == "LIKELY_VULNERABLE"
    assert cve_2026_65878.classify_version("6.7.0") == "LIKELY_VULNERABLE"
    assert cve_2026_65878.classify_version("6.7.1") == "NOT_AFFECTED"
    assert cve_2026_65878.classify_version("6.10.0") == "NOT_AFFECTED"
    assert cve_2026_65878.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_passive_result_vulnerable() -> None:
    finding = cve_2026_65878.passive_result(
        {"sppagebuilder": {"found": True, "version": "6.0.0"}}
    )
    assert finding.status == "LIKELY_VULNERABLE"
    assert finding.component_version == "6.0.0"


def test_passive_result_not_detected() -> None:
    finding = cve_2026_65878.passive_result({})
    assert finding.status == "NOT_DETECTED"


def test_replace_path_by_title_matches_pre_fix_php() -> None:
    assert (
        cve_2026_65878.replace_path_by_title("images/foo/jpg.jpg", "php")
        == "images/foo/php.php"
    )
    assert (
        cve_2026_65878.replace_path_by_title(
            "proofcms-65878-canary.txt", "proofcms-65878-renamed"
        )
        == "proofcms-65878-renamed.txt"
    )
    assert cve_2026_65878.replace_path_by_title("", "x") == ""


def test_aggressive_without_credentials_is_blocked() -> None:
    finding = cve_2026_65878.run_aggressive_probe("https://fixture.test")
    assert finding.status == "BLOCKED_EXTERNAL"
    assert finding.exploit_ran is False


def test_metadata() -> None:
    meta = cve_2026_65878.metadata()
    assert meta["cve"] == "CVE-2026-65878"
    assert meta["exploit_modes"] == ["safe", "aggressive"]
    assert meta["required_detectors"] == ["sppagebuilder"]
