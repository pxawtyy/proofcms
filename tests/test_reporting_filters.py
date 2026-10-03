from proofcms.reporting.console import visible_results

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
