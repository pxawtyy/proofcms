from proofcms.modules.joomla import cve_2026_56292, cve_2026_94132


def inventory(version: str, edition: str | None = None) -> dict:
    return {
        "acymailing": {
            "found": True,
            "version": version,
            "edition": edition,
            "source": "/administrator/components/com_acymailing/acymailing.xml",
        }
    }


def test_acymailing_581_matches_critical_sqli_range():
    result = cve_2026_56292.check("https://target.test", plugins=inventory("5.8.1"))
    assert result.status == "LIKELY_VULNERABLE"
    assert result.confidence == "HIGH"


def test_acymailing_enterprise_581_matches_mailbox_rce_range():
    result = cve_2026_94132.check("https://target.test", plugins=inventory("5.8.1", "enterprise"))
    assert result.status == "LIKELY_VULNERABLE"


def test_mailbox_rce_does_not_assume_enterprise_edition():
    result = cve_2026_94132.check("https://target.test", plugins=inventory("5.8.1"))
    assert result.status == "INCONCLUSIVE"


def test_acymailing_fixed_versions_are_patched():
    assert cve_2026_56292.check("https://target.test", plugins=inventory("10.11.1")).status == "PATCHED"
    assert cve_2026_94132.check(
        "https://target.test", plugins=inventory("11.1.0", "enterprise")
    ).status == "PATCHED"
