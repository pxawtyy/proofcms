from unittest.mock import patch

from proofcms.modules.generic import cve_2026_126187 as flight


def test_metadata_registers_safe_and_aggressive_modes():
    meta = flight.metadata()
    assert meta["cve"] == "CVE-2026-126187"
    assert meta["exploit_modes"] == ["safe", "aggressive"]
    assert meta["intrusive"] is True
    assert "19.3.0" in meta["affected_versions"]
    assert "Next.js 16.0.0-16.4.0" in meta["affected_versions"]


def test_build_blob_places_forged_rows_at_resume_offset():
    forged = '4:{"marker":"PROOFCMS_126187_test"}\n'
    blob, resume_at, length = flight._build_blob(forged, "4", 8192)
    assert len(blob) == length
    assert blob[resume_at : resume_at + len(forged)] == forged.encode()
    assert resume_at < 8192


def test_extract_summary_reads_pre_json():
    page = '<html><pre>{"block0":8192,"annotation":{"marker":"x"}}</pre></html>'
    summary = flight._extract_summary(page)
    assert summary["block0"] == 8192
    assert summary["annotation"]["marker"] == "x"


def test_check_without_probe_is_not_confirmed():
    detected = {"detected": True, "markers": ["next_f"], "status": 200}
    with patch.object(flight, "detect_rsc", return_value=detected):
        finding = flight.check("https://fixture.test", timeout=1)
    assert finding.status == "NOT_CONFIRMED"
    assert finding.confidence == "MEDIUM"


def test_check_no_rsc_is_not_detected():
    detected = {"detected": False, "markers": [], "status": 200}
    with patch.object(flight, "detect_rsc", return_value=detected):
        finding = flight.check("https://fixture.test", timeout=1)
    assert finding.status == "NOT_DETECTED"
    assert finding.confidence == "LOW"


def test_check_safe_probe_marks_vulnerable_without_action():
    detected = {"detected": True, "markers": ["next_f"], "status": 200}
    proof = {
        "confirmed": True,
        "marker": "PROOFCMS_126187_deadbeef",
        "chunk_id": "4",
        "overread": 8192,
        "blob_length": 8250,
        "resume_at": 8182,
        "attempts": [],
    }
    with (
        patch.object(flight, "detect_rsc", return_value=detected),
        patch.object(flight, "safe_probe", return_value=proof),
    ):
        finding = flight.check(
            "https://fixture.test",
            run_exploit_check=True,
            exploit_mode="safe",
            timeout=1,
        )
    assert finding.status == "VULNERABLE"
    assert finding.confidence == "CONFIRMED"
    assert finding.exploit_ran is True
    assert "No Server Action was executed" in finding.detail


def test_check_aggressive_probe_marks_vulnerable_with_marker():
    detected = {"detected": True, "markers": ["next_f"], "status": 200}
    proof = {
        "confirmed": True,
        "marker": "PROOFCMS_126187_deadbeef",
        "action_id": "a" * 40,
        "chunk_id": "4",
        "overread": 8192,
        "blob_length": 8300,
        "resume_at": 8182,
        "attempts": [],
    }
    with (
        patch.object(flight, "detect_rsc", return_value=detected),
        patch.object(flight, "aggressive_probe", return_value=proof),
    ):
        finding = flight.check(
            "https://fixture.test",
            run_exploit_check=True,
            exploit_mode="aggressive",
            timeout=1,
        )
    assert finding.status == "VULNERABLE"
    assert finding.confidence == "CONFIRMED"
    assert finding.exploit_ran is True
    assert "Server Action" in finding.detail


def test_check_aggressive_without_action_id_is_not_confirmed():
    detected = {"detected": True, "markers": ["next_f"], "status": 200}
    proof = {"confirmed": False, "marker": "x", "action_id": None, "error": "no action"}
    with (
        patch.object(flight, "detect_rsc", return_value=detected),
        patch.object(flight, "aggressive_probe", return_value=proof),
    ):
        finding = flight.check(
            "https://fixture.test",
            run_exploit_check=True,
            exploit_mode="aggressive",
            timeout=1,
        )
    assert finding.status == "NOT_CONFIRMED"
    assert finding.confidence == "HIGH"
