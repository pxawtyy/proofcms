from proofcms.modules.joomla import cve_2026_129393 as media_rce


def test_129393_version_boundaries():
    assert media_rce.classify_version("4.0.0") == "LIKELY_VULNERABLE"
    assert media_rce.classify_version("5.4.10") == "LIKELY_VULNERABLE"
    assert media_rce.classify_version("5.4.11") == "PATCHED"
    assert media_rce.classify_version("6.0.0") == "LIKELY_VULNERABLE"
    assert media_rce.classify_version("6.2.0") == "LIKELY_VULNERABLE"
    assert media_rce.classify_version("6.2.1") == "PATCHED"
    assert media_rce.classify_version("3.10.12") == "NOT_AFFECTED"
    assert media_rce.classify_version(None) == "INCONCLUSIVE"


def test_129393_passive_result_and_no_active_probe():
    vulnerable = media_rce.check("https://target.test", joomla_version="5.4.10")
    assert vulnerable.status == "LIKELY_VULNERABLE"
    assert vulnerable.exploit_available is False
    assert "5.4.11" in vulnerable.action

    patched = media_rce.check("https://target.test", joomla_version="5.4.11")
    assert patched.status == "PATCHED"

    unknown = media_rce.check("https://target.test")
    assert unknown.status == "INCONCLUSIVE"

    active = media_rce.check(
        "https://target.test",
        joomla_version="5.4.10",
        run_exploit_check=True,
    )
    assert "No active proof" in active.detail


def test_129393_metadata_contract():
    meta = media_rce.metadata()
    assert meta["cve"] == "CVE-2026-129393"
    assert meta["cms"] == "joomla"
    assert meta["exploit_available"] is False
    assert meta["exploit_modes"] == []
    assert meta["vulnerability_type"] == "Remote Code Execution"
    assert meta["affected_joomla_versions"] == ["4.0.0-5.4.10", "6.0.0-6.2.0"]
