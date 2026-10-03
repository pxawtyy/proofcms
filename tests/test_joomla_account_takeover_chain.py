from proofcms.chains.joomla_account_takeover import aggregate


def _result(cve: str, status: str) -> dict[str, str]:
    return {"cve": cve, "status": status}


def test_chain_is_likely_when_both_registration_flaws_match():
    result = aggregate(
        [
            _result("CVE-2016-8870", "LIKELY_VULNERABLE"),
            _result("CVE-2016-8869", "LIKELY_VULNERABLE"),
        ]
    )
    assert result["status"] == "LIKELY_VULNERABLE"
    assert result["confidence"] == "HIGH"
    assert "No user was created" in result["detail"]


def test_chain_is_not_affected_when_one_prerequisite_is_patched():
    result = aggregate(
        [
            _result("CVE-2016-8870", "LIKELY_VULNERABLE"),
            _result("CVE-2016-8869", "PATCHED"),
        ]
    )
    assert result["status"] == "NOT_AFFECTED"


def test_chain_is_inconclusive_when_component_is_missing():
    result = aggregate([_result("CVE-2016-8870", "LIKELY_VULNERABLE")])
    assert result["status"] == "INCONCLUSIVE"


def test_chain_handles_confirmed_account_and_likely_privilege_assignment():
    result = aggregate(
        [
            _result("CVE-2016-8870", "VULNERABLE"),
            _result("CVE-2016-8869", "LIKELY_VULNERABLE"),
        ]
    )
    assert result["status"] == "LIKELY_VULNERABLE"
    assert result["confidence"] == "HIGH"
