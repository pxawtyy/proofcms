from __future__ import annotations

from proofcms.modules.joomla import cve_2026_105606, cve_2026_107904


def test_customtables_105606_version_boundaries():
    assert cve_2026_105606.classify_version("3.7.7") == "LIKELY_VULNERABLE"
    assert cve_2026_105606.classify_version("3.7.8") == "NOT_AFFECTED"
    assert cve_2026_105606.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_customtables_105606_passive_result():
    result = cve_2026_105606.passive_result({"customtables": {"found": True, "version": "3.7.7"}})
    assert result.status == "LIKELY_VULNERABLE"


def test_easyfileuploader_107904_version_boundaries():
    assert cve_2026_107904.classify_version("2.9.2.1") == "LIKELY_VULNERABLE"
    assert cve_2026_107904.classify_version("2.9.6") == "LIKELY_VULNERABLE"
    assert cve_2026_107904.classify_version("2.9.7") == "NOT_AFFECTED"
    assert cve_2026_107904.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_easyfileuploader_107904_passive_result():
    result = cve_2026_107904.passive_result({"easyfileuploader": {"found": True, "version": "2.9.2.1"}})
    assert result.status == "LIKELY_VULNERABLE"
