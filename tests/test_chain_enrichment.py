from __future__ import annotations

from proofcms.chains import AVAILABLE_CHAINS
from proofcms.chains.joomla_session_to_upload import aggregate as session_to_upload
from proofcms.chains.joomla_token_to_upload import aggregate as token_to_upload
from proofcms.chains.phpinfo_origin_bypass import aggregate as phpinfo_origin
from proofcms.modules.generic import AVAILABLE_CVES as GENERIC_CVES
from proofcms.modules.joomla import AVAILABLE_CVES as JOOMLA_CVES
from proofcms.modules.php import AVAILABLE_CVES as PHP_CVES
from proofcms.modules.wordpress import AVAILABLE_CVES as WORDPRESS_CVES

ALL_CVES = {**WORDPRESS_CVES, **JOOMLA_CVES, **GENERIC_CVES, **PHP_CVES}


def _result(cve: str, status: str) -> dict[str, str]:
    return {"cve": cve, "status": status}


def test_registered_chain_cves_are_real_modules():
    for chain_id, chain in AVAILABLE_CHAINS.items():
        for cve in chain["cves"]:
            assert cve in ALL_CVES, f"{chain_id} references unregistered {cve}"
        assert callable(chain["aggregate"])


def test_phpinfo_origin_chain_confirmed_primitives():
    result = phpinfo_origin(
        [
            _result("PROOFCMS-PHPINFO-EXPOSURE", "VULNERABLE"),
            _result("PROOFCMS-ORIGIN-DIRECT-ACCESS", "VULNERABLE"),
            _result("CVE-2024-4577", "VULNERABLE"),
            _result("CVE-2019-11043", "PATCHED"),
        ]
    )
    assert result["status"] == "LIKELY_VULNERABLE"
    assert result["confidence"] == "HIGH"
    assert result["component_statuses"]["CVE-2024-4577"] == "VULNERABLE"
    assert "not executed end-to-end" in result["detail"]


def test_phpinfo_origin_chain_likely_php_primitive():
    result = phpinfo_origin(
        [
            _result("PROOFCMS-PHPINFO-EXPOSURE", "VULNERABLE"),
            _result("PROOFCMS-ORIGIN-DIRECT-ACCESS", "VULNERABLE"),
            _result("CVE-2019-11043", "LIKELY_VULNERABLE"),
        ]
    )
    assert result["status"] == "LIKELY_VULNERABLE"
    assert result["confidence"] == "MEDIUM"


def test_phpinfo_origin_chain_not_affected_when_php_is_patched():
    result = phpinfo_origin(
        [
            _result("PROOFCMS-PHPINFO-EXPOSURE", "VULNERABLE"),
            _result("PROOFCMS-ORIGIN-DIRECT-ACCESS", "VULNERABLE"),
            _result("CVE-2019-11043", "PATCHED"),
            _result("CVE-2024-4577", "NOT_AFFECTED"),
        ]
    )
    assert result["status"] == "NOT_AFFECTED"


def test_phpinfo_origin_chain_inconclusive_without_recon():
    result = phpinfo_origin([_result("CVE-2024-4577", "VULNERABLE")])
    assert result["status"] == "INCONCLUSIVE"


def test_session_to_upload_chain_confirmed_primitives():
    result = session_to_upload(
        [
            _result("CVE-2026-90907", "VULNERABLE"),
            _result("CVE-2026-105603", "VULNERABLE_UPLOAD_ONLY"),
        ]
    )
    assert result["status"] == "LIKELY_VULNERABLE"
    assert result["confidence"] == "HIGH"
    assert "CVE-2026-90907" in result["detail"]


def test_session_to_upload_chain_likely_primitives():
    result = session_to_upload(
        [
            _result("CVE-2026-48897", "LIKELY_VULNERABLE"),
            _result("CVE-2026-105603", "LIKELY_VULNERABLE"),
        ]
    )
    assert result["status"] == "LIKELY_VULNERABLE"
    assert result["confidence"] == "MEDIUM"


def test_session_to_upload_chain_not_affected_when_upload_is_patched():
    result = session_to_upload(
        [
            _result("CVE-2026-90907", "VULNERABLE"),
            _result("CVE-2026-105603", "PATCHED"),
        ]
    )
    assert result["status"] == "NOT_AFFECTED"


def test_session_to_upload_chain_not_affected_when_all_sessions_are_patched():
    result = session_to_upload(
        [
            _result("CVE-2026-90907", "PATCHED"),
            _result("CVE-2026-48897", "NOT_AFFECTED"),
            _result("CVE-2026-92227", "PATCHED"),
            _result("CVE-2026-105603", "VULNERABLE_UPLOAD_ONLY"),
        ]
    )
    assert result["status"] == "NOT_AFFECTED"


def test_token_to_upload_chain_confirmed_primitives():
    result = token_to_upload(
        [
            _result("CVE-2026-21627", "VULNERABLE"),
            _result("CVE-2026-105606", "VULNERABLE_UPLOAD_ONLY"),
        ]
    )
    assert result["status"] == "LIKELY_VULNERABLE"
    assert result["confidence"] == "HIGH"
    assert "same token was not replayed" in result["detail"]


def test_token_to_upload_chain_likely_primitives():
    result = token_to_upload(
        [
            _result("CVE-2026-21627", "LIKELY_VULNERABLE"),
            _result("CVE-2026-105606", "LIKELY_VULNERABLE"),
        ]
    )
    assert result["status"] == "LIKELY_VULNERABLE"
    assert result["confidence"] == "MEDIUM"


def test_token_to_upload_chain_not_affected_when_token_is_patched():
    result = token_to_upload(
        [
            _result("CVE-2026-21627", "PATCHED"),
            _result("CVE-2026-105606", "VULNERABLE_UPLOAD_ONLY"),
        ]
    )
    assert result["status"] == "NOT_AFFECTED"
