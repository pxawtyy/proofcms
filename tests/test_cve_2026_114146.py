from __future__ import annotations

from proofcms.modules.generic import cve_2026_114146


def test_package_version_boundaries() -> None:
    assert cve_2026_114146.classify_version("1.2.0") == "LIKELY_VULNERABLE"
    assert cve_2026_114146.classify_version("1.2.13") == "LIKELY_VULNERABLE"
    assert cve_2026_114146.classify_version("1.2.14") == "PATCHED"
    assert cve_2026_114146.classify_version("1.1.0") == "NOT_AFFECTED"


def test_runtime_version_boundaries() -> None:
    assert cve_2026_114146.classify_version("8.0.0") == "LIKELY_VULNERABLE"
    assert cve_2026_114146.classify_version("8.0.33") == "LIKELY_VULNERABLE"
    assert cve_2026_114146.classify_version("8.0.34") == "PATCHED"
    assert cve_2026_114146.classify_version("9.0.22") == "LIKELY_VULNERABLE"
    assert cve_2026_114146.classify_version("9.0.23") == "PATCHED"
    assert cve_2026_114146.classify_version("10.0.14") == "LIKELY_VULNERABLE"
    assert cve_2026_114146.classify_version("10.0.15") == "PATCHED"
    assert cve_2026_114146.classify_version("11.0.0-rc.3") == "LIKELY_VULNERABLE"
    assert cve_2026_114146.classify_version("11.0.0") == "PATCHED"
    assert cve_2026_114146.classify_version("7.0.20") == "NOT_AFFECTED"
    assert cve_2026_114146.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_passive_result_vulnerable() -> None:
    finding = cve_2026_114146.passive_result("8.0.33")
    assert finding.status == "LIKELY_VULNERABLE"
    assert finding.component_version == "8.0.33"


def test_aggressive_without_accounts_is_blocked() -> None:
    finding = cve_2026_114146.run_aggressive_probe("https://fixture.test")
    assert finding.status == "BLOCKED_EXTERNAL"
    assert finding.exploit_ran is False


def test_metadata() -> None:
    meta = cve_2026_114146.metadata()
    assert meta["cve"] == "CVE-2026-114146"
    assert meta["exploit_modes"] == ["safe", "aggressive"]
    assert meta["required_detectors"] == ["aspnet"]
