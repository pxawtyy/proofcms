from unittest.mock import patch

from proofcms.core.categories import VulnerabilityType
from proofcms.modules.php import cve_2026_109618, cve_2026_109619


class _OrderedPidSession:
    """Serve scripted pid reads in order, then a fixed POST outcome."""

    base_url = "http://lab.test"

    def __init__(self, pid_bodies, post):
        self._reads = list(pid_bodies)
        self._post = post
        self.transcript = []

    def get(self, url, timeout=None):
        assert url == "/pid.php"
        return {"status": 200, "body": self._reads.pop(0)}

    def post(self, url, data=None, headers=None, timeout=None):
        assert url == "/index.php"
        return dict(self._post)


def test_php_109618_branch_boundaries():
    assert cve_2026_109618.classify_version("8.2.34") == "LIKELY_VULNERABLE"
    assert cve_2026_109618.classify_version("8.2.35") == "PATCHED"
    assert cve_2026_109618.classify_version("8.3.35") == "LIKELY_VULNERABLE"
    assert cve_2026_109618.classify_version("8.4.27") == "PATCHED"
    assert cve_2026_109618.classify_version("8.5.12") == "PATCHED"


def test_php_109619_marks_legacy_builds_package_specific():
    assert cve_2026_109619.classify_version("7.4.33") == "NOT_CONFIRMED"
    result = cve_2026_109619.check(
        "https://fixture.test",
        php_runtime={"detected": True, "version": "7.4.33", "source": "/:X-Powered-By"},
    )
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["package_backport_required"] is True
    assert result.evidence["active_probe"] == "not_sent"


def test_php_2026_advisories_are_memory_corruption_and_passive():
    runtime = {"detected": True, "version": "8.4.26", "source": "/:X-Powered-By"}
    result = cve_2026_109619.check("https://fixture.test", php_runtime=runtime)
    assert result.status == "LIKELY_VULNERABLE"
    assert result.vulnerability_type == VulnerabilityType.MEMORY_CORRUPTION
    assert result.exploit_ran is False


def test_109618_crash_with_pid_respawn_confirms():
    sess = _OrderedPidSession(
        ["PID=10 PHP=8.3.35\nPID_OK\n", "PID=11 PHP=8.3.35\nPID_OK\n"],
        {"status": 0, "body": "", "error": {"type": "RemoteDisconnected", "message": "reset"}},
    )
    with patch.object(cve_2026_109618, "HttpSession", return_value=sess):
        result = cve_2026_109618.run_aggressive_probe("http://lab.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["pid_changed"] is True
    assert result.evidence["send_status"] == 0


def test_109618_clean_fatal_with_same_pid_does_not_confirm():
    sess = _OrderedPidSession(
        ["PID=31 PHP=8.3.36\nPID_OK\n", "PID=31 PHP=8.3.36\nPID_OK\n"],
        {
            "status": 200,
            "body": "<b>Fatal error</b>: Allowed memory size of 16777216 bytes exhausted in <b>Unknown</b> on line <b>0</b>",
        },
    )
    with patch.object(cve_2026_109618, "HttpSession", return_value=sess):
        result = cve_2026_109618.run_aggressive_probe("http://lab.test")
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["fatal_memory_text"] is True


def test_109618_missing_pid_endpoint_skips_payload():
    posts = {"n": 0}

    class NoPidSession:
        base_url = "http://lab.test"

        def __init__(self):
            self.transcript = []

        def get(self, url, timeout=None):
            return {"status": 404, "body": "missing"}

        def post(self, url, data=None, headers=None, timeout=None):
            posts["n"] += 1
            return {"status": 200, "body": "OK"}

    with patch.object(cve_2026_109618, "HttpSession", return_value=NoPidSession()):
        result = cve_2026_109618.run_aggressive_probe("http://lab.test")
    assert result.status == "NOT_CONFIRMED"
    assert posts["n"] == 0


def test_109618_patched_version_skips_probe():
    with patch.object(cve_2026_109618, "run_aggressive_probe") as probe:
        result = cve_2026_109618.check(
            "https://fixture.test",
            php_runtime={"detected": True, "version": "8.3.36", "source": "/:X-Powered-By"},
            run_exploit_check=True,
            exploit_mode="aggressive",
        )
    assert result.status == "PATCHED"
    probe.assert_not_called()


def _109619_script(responses):
    calls = {"n": 0}

    def fake_exchange(host, port, request, timeout, read_cap=1 << 20):
        calls["n"] += 1
        return dict(responses[min(calls["n"] - 1, len(responses) - 1)])

    return fake_exchange, calls


def test_109619_dead_followup_with_live_control_confirms():
    from proofcms.modules.php import cve_2026_109619

    fake, _ = _109619_script(
        [
            {"status": 200, "body": "SID=abc123\nOK\n", "headers": {}},
            {"status": 200, "body": "fatal", "headers": {}},
            {"status": 0, "body": "", "headers": {}},
            {"status": 200, "body": "SID=xyz\nOK\n", "headers": {}},
        ]
    )
    with patch.object(cve_2026_109619, "_raw_exchange", side_effect=fake):
        result = cve_2026_109619.run_aggressive_probe("http://lab.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["followup_status"] == 0
    assert result.evidence["control_status"] == 200


def test_109619_clean_followup_does_not_confirm():
    from proofcms.modules.php import cve_2026_109619

    fake, _ = _109619_script(
        [
            {"status": 200, "body": "SID=abc123\nOK\n", "headers": {}},
            {"status": 200, "body": "fatal", "headers": {}},
            {
                "status": 200,
                "body": "SID=other\nOK\n",
                "headers": {"set-cookie": ["PHPSESSID=freshcookie12345678901234567890; path=/"]},
            },
            {"status": 200, "body": "SID=zzz\nOK\n", "headers": {}},
        ]
    )
    with patch.object(cve_2026_109619, "_raw_exchange", side_effect=fake):
        result = cve_2026_109619.run_aggressive_probe("http://lab.test")
    assert result.status == "NOT_CONFIRMED"


def test_109619_dead_control_is_inconclusive():
    from proofcms.modules.php import cve_2026_109619

    fake, _ = _109619_script(
        [
            {"status": 200, "body": "SID=abc123\nOK\n", "headers": {}},
            {"status": 200, "body": "fatal", "headers": {}},
            {"status": 0, "body": "", "headers": {}},
            {"status": 0, "body": "", "headers": {}},
        ]
    )
    with patch.object(cve_2026_109619, "_raw_exchange", side_effect=fake):
        result = cve_2026_109619.run_aggressive_probe("http://lab.test")
    assert result.status == "NOT_CONFIRMED"
    assert result.confidence == "LOW"
