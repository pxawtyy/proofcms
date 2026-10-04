from unittest.mock import patch

from proofcms.modules.joomla import cve_2019_19576, cve_2019_19634
from proofcms.modules.joomla.k2_upload_probe import (
    _category_id,
    _hidden_fields,
)

K2_268 = {"k2": {"found": True, "version": "2.6.8", "source": "/administrator/components/com_k2/k2.xml"}}


def test_k2_268_is_affected_by_both_critical_cves():
    for module in (cve_2019_19576, cve_2019_19634):
        result = module.check("https://target.test", plugins=K2_268)
        assert result.status == "LIKELY_VULNERABLE"
        assert result.confidence == "HIGH"
        assert result.component_version == "2.6.8"


def test_k2_inert_phar_readback_confirms_upload_filter_bypass():
    proof = {
        "form_found": True,
        "accepted": True,
        "proof_url": "https://target.test/media/k2/attachments/proof.phar",
        "filename": "proof.phar",
    }
    with patch(
        "proofcms.modules.joomla.k2_dangerous_extension.probe_inert_extension",
        return_value=proof,
    ):
        result = cve_2019_19576.check(
            "https://target.test",
            plugins=K2_268,
            run_exploit_check=True,
            exploit_mode="aggressive",
        )
    assert result.status == "VULNERABLE_UPLOAD_ONLY"
    assert result.confidence == "CONFIRMED"
    assert result.uploaded_filename == "proof.phar"


def test_k2_generic_200_without_marker_does_not_confirm():
    proof = {
        "form_found": True,
        "accepted": False,
        "upload": {"status": 200, "redirected": True},
    }
    with patch(
        "proofcms.modules.joomla.k2_dangerous_extension.probe_inert_extension",
        return_value=proof,
    ):
        result = cve_2019_19634.check(
            "https://target.test",
            plugins=K2_268,
            run_exploit_check=True,
            exploit_mode="aggressive",
        )
    assert result.status == "NOT_CONFIRMED"
    assert result.uploaded_filename is None


def test_k2_form_helpers_extract_real_legacy_fields():
    html = """
    <input type="hidden" name="option" value="com_k2">
    <input type="hidden" name="0123456789abcdef0123456789abcdef" value="1">
    <select name="catid"><option value="0">Select</option><option value="7">News</option></select>
    """
    assert _hidden_fields(html)["option"] == "com_k2"
    assert _category_id(html) == "7"


def test_k2_fixed_release_is_patched():
    plugins = {"k2": {"found": True, "version": "2.11.20240911", "source": "manifest"}}
    result = cve_2019_19576.check("https://target.test", plugins=plugins)
    assert result.status == "PATCHED"
