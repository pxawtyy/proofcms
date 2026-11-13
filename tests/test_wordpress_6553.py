from unittest.mock import patch

from proofcms.modules.wordpress import cve_2023_6553
from proofcms.modules.wordpress.php_filter_chain import build_chain

PLUGINS = {
    "backup-backup": {
        "found": True,
        "version": "1.3.7",
        "source": "/wp-content/plugins/backup-backup/readme.txt",
        "version_confidence": "HIGH",
    }
}


def test_6553_version_boundaries():
    assert cve_2023_6553.classify_version("1.0.7") == "NOT_AFFECTED"
    assert cve_2023_6553.classify_version("1.0.8") == "LIKELY_VULNERABLE"
    assert cve_2023_6553.classify_version("1.3.7") == "LIKELY_VULNERABLE"
    assert cve_2023_6553.classify_version("1.3.8") == "PATCHED"
    assert cve_2023_6553.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_6553_probe_confirms_sleep_differential():
    control = {"elapsed": 0.02, "status": 200, "blocked": False, "chain_length": 3550}
    proof = {"elapsed": 4.02, "status": 200, "blocked": False, "chain_length": 3489}
    with patch.object(cve_2023_6553, "_timed_include", side_effect=[control, proof]):
        result = cve_2023_6553.run_safe_probe("https://fixture.test", timeout=1)
    assert result["confirmed"] is True
    assert result["proof"]["elapsed"] == 4.02


def test_6553_probe_rejects_fast_proof():
    control = {"elapsed": 0.02, "status": 200, "blocked": False, "chain_length": 3550}
    proof = {"elapsed": 0.05, "status": 200, "blocked": False, "chain_length": 3489}
    with patch.object(cve_2023_6553, "_timed_include", side_effect=[control, proof]):
        result = cve_2023_6553.run_safe_probe("https://fixture.test", timeout=1)
    assert result["confirmed"] is False


def test_6553_check_promotes_confirmed_probe():
    probe = {
        "confirmed": True,
        "blocked": False,
        "control": {"elapsed": 0.02},
        "proof": {"elapsed": 4.02},
        "proof_url": "https://fixture.test/x",
    }
    with patch.object(cve_2023_6553, "run_safe_probe", return_value=probe):
        result = cve_2023_6553.check(
            "https://fixture.test",
            run_exploit_check=True,
            exploit_mode="safe",
            plugins=PLUGINS,
            timeout=1,
        )
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.exploit_ran is True


def test_6553_check_patched_version_skips_probe():
    patched = {"backup-backup": {**PLUGINS["backup-backup"], "version": "1.3.8"}}
    with patch.object(cve_2023_6553, "run_safe_probe") as probe:
        result = cve_2023_6553.check(
            "https://fixture.test",
            run_exploit_check=True,
            exploit_mode="safe",
            plugins=patched,
            timeout=1,
        )
    probe.assert_not_called()
    assert result.status == "PATCHED"


def test_6553_blocked_probe_is_not_confirmed():
    probe = {"confirmed": False, "blocked": True, "control": {}, "proof": {}, "proof_url": "https://fixture.test/x"}
    with patch.object(cve_2023_6553, "run_safe_probe", return_value=probe):
        result = cve_2023_6553.check(
            "https://fixture.test",
            run_exploit_check=True,
            exploit_mode="safe",
            plugins=PLUGINS,
            timeout=1,
        )
    assert result.status == "NOT_CONFIRMED"
    assert result.confidence == "HIGH"


def test_6553_filter_chain_shape():
    chain = build_chain("<?php sleep(0);?>")
    assert chain.startswith("php://filter/")
    assert chain.endswith("/resource=php://temp")
    assert len(chain) > 1000
    assert build_chain("<?php sleep(0);?>") == chain


def test_6553_metadata_is_safe():
    metadata = cve_2023_6553.metadata()
    assert metadata["exploit_modes"] == ["safe"]
    assert metadata["intrusive"] is False
    assert metadata["vulnerability_type"] == "Remote Code Execution"
