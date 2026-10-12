from proofcms.reporting.console import print_live_result, visible_results

RESULTS = [
    {"cve": "CVE-A", "status": "VULNERABLE"},
    {"cve": "CVE-B", "status": "PATCHED"},
    {"cve": "CVE-C", "status": "NOT_DETECTED"},
    {"cve": "CVE-D", "status": "NOT_AFFECTED"},
]


def test_default_hides_patched_and_not_detected():
    visible, hidden = visible_results(RESULTS)
    assert [result["cve"] for result in visible] == ["CVE-A"]
    assert hidden == {"PATCHED": 1, "NOT_DETECTED": 1, "NOT_AFFECTED": 1}


def test_show_not_detected_does_not_also_show_patched():
    visible, _ = visible_results(RESULTS, show_not_detected=True)
    assert [result["cve"] for result in visible] == ["CVE-A", "CVE-C"]


def test_show_all_disables_both_filters():
    visible, hidden = visible_results(RESULTS, show_all=True)
    assert visible == RESULTS
    assert hidden == {"PATCHED": 0, "NOT_DETECTED": 0, "NOT_AFFECTED": 0}


def test_live_result_prints_immediately_and_honors_filters(capsys):
    finding = {
        "cve": "CVE-LIVE",
        "status": "VULNERABLE",
        "confidence": "HIGH",
        "vulnerability_type": "Cross-Site Scripting (XSS)",
        "component": "Joomla core",
        "component_version": "4.4.0",
        "affected_rule": "test range",
        "detail": "live detail",
        "action": "upgrade",
    }
    assert print_live_result(finding) is True
    assert "CVE-LIVE: VULNERABLE" in capsys.readouterr().out

    finding["status"] = "PATCHED"
    assert print_live_result(finding) is False
    assert capsys.readouterr().out == ""
    assert print_live_result(finding, show_all=True) is True
    assert "CVE-LIVE: PATCHED" in capsys.readouterr().out
