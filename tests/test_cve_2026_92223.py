from __future__ import annotations

from proofcms.modules.joomla import cve_2026_92223


def test_version_classification() -> None:
    assert cve_2026_92223.classify_version("4.4.13") == "NOT_AFFECTED"
    assert cve_2026_92223.classify_version("5.0.0") == "LIKELY_VULNERABLE"
    assert cve_2026_92223.classify_version("5.4.8") == "LIKELY_VULNERABLE"
    assert cve_2026_92223.classify_version("5.4.9") == "PATCHED"
    assert cve_2026_92223.classify_version("6.0.0") == "LIKELY_VULNERABLE"
    assert cve_2026_92223.classify_version("6.1.3") == "LIKELY_VULNERABLE"
    assert cve_2026_92223.classify_version("6.1.4") == "PATCHED"
    assert cve_2026_92223.classify_version(None) == "INCONCLUSIVE"


def test_stage_title_parsing() -> None:
    html = (
        '<td class="article-stage"><div id="workflow-1" role="tooltip">'
        "<strong>ProofCMS Review</strong><br>Workflow: Basic Workflow</div></td>"
    )
    assert cve_2026_92223.stage_title(html, 1) == "ProofCMS Review"
    assert cve_2026_92223.stage_title(html, 2) is None
    assert cve_2026_92223.stage_title("", 1) is None


def test_aggressive_without_arguments_is_blocked() -> None:
    finding = cve_2026_92223.run_aggressive_probe("https://fixture.test")
    assert finding.status == "BLOCKED_EXTERNAL"
    assert finding.exploit_ran is False


def test_metadata() -> None:
    meta = cve_2026_92223.metadata()
    assert meta["cve"] == "CVE-2026-92223"
    assert meta["exploit_modes"] == ["safe", "aggressive"]
    assert meta["privileges_required"] == "HIGH"
