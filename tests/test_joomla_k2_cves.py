from unittest.mock import patch

from proofcms.modules.joomla import cve_2019_19576, cve_2019_19634
from proofcms.modules.joomla.k2_upload_probe import (
    _category_id,
    _hidden_fields,
    discover_backend_form,
    probe_backend_attachment,
)

K2_268 = {"k2": {"found": True, "version": "2.6.8", "source": "/administrator/components/com_k2/k2.xml"}}
K2_280 = {"k2": {"found": True, "version": "2.8.0", "source": "/administrator/components/com_k2/k2.xml"}}
K2_211 = {"k2": {"found": True, "version": "2.11.20240911", "source": "manifest"}}
K2_227 = {"k2": {"found": True, "version": "2.27", "source": "manifest"}}
K2_228 = {"k2": {"found": True, "version": "2.28", "source": "manifest"}}

BACKEND_FORM = """
<form action="index.php" method="post" name="adminForm" id="adminForm">
<input type="hidden" name="option" value="com_k2">
<input type="hidden" name="view" value="item">
<input type="hidden" name="task" value="">
<input type="hidden" name="isSite" value="0">
<input type="hidden" name="id" value="">
<input type="hidden" name="0123456789abcdef0123456789abcdef" value="1">
<select name="catid"><option value="0" selected="selected">- Select -</option><option value="1">Lab</option></select>
<a href="#k2Tab6">Attachments</a>
</form>
"""


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


def test_k2_category_prefers_real_category_over_selected_placeholder():
    html = """
    <select name="catid"><option value="0" selected="selected">- Select category -</option><option value="1">Lab</option></select>
    """
    assert _category_id(html) == "1"


def test_k2_backend_form_discovery_parses_token_and_category():
    class Session:
        base_url = "https://target.test"

        def get(self, path):
            assert "com_k2" in path
            return {"status": 200, "body": BACKEND_FORM, "redirected": False}

    form = discover_backend_form(Session())
    assert form["token"] == "0123456789abcdef0123456789abcdef"
    assert form["category"] == "1"
    assert form["fields"]["option"] == "com_k2"


def test_k2_backend_probe_confirms_marker_readback():
    class Session:
        def __init__(self, base_url=None, **kwargs):
            self.base_url = base_url or "https://target.test"
            self.marker = None

        def get(self, path):
            if "com_k2" in path:
                return {"status": 200, "body": BACKEND_FORM, "redirected": False}
            if path.endswith(".phar"):
                return {"status": 200, "body": f"binary-blob-{self.marker}-blob", "redirected": False}
            return {"status": 404, "body": "missing", "redirected": False}

        def post(self, url, fields, files):
            assert fields["task"] == "save"
            assert fields["catid"] == "1"
            name, payload, content_type = files["attachment_file[]"]
            assert name.endswith(".phar")
            assert content_type == "application/octet-stream"
            self.marker = fields["attachment_title[]"]
            assert self.marker.encode() in payload
            return {"status": 303, "body": "", "redirected": True, "final_url": "https://target.test/items"}

    with (
        patch("proofcms.modules.joomla.k2_upload_probe.HttpSession", Session),
        patch("proofcms.modules.joomla.k2_upload_probe.joomla_admin_login", return_value=True),
    ):
        result = probe_backend_attachment(
            "https://target.test", "phar", "admin", "secret"
        )
    assert result["form_found"] is True
    assert result["accepted"] is True
    assert result["proof_url"].endswith(".phar")


def test_k2_backend_probe_requires_admin_login():
    with patch(
        "proofcms.modules.joomla.k2_upload_probe.joomla_admin_login", return_value=False
    ):
        result = probe_backend_attachment(
            "https://target.test", "pht", "admin", "wrong"
        )
    assert result["accepted"] is False
    assert result["form_found"] is False


def test_k2_211_still_affected_despite_2024_library_fix():
    # Live-lab evidence (2026-11-10): K2 2.11.20240911 stores and serves a
    # plain .phar/.pht attachment because the item model forces
    # file_new_name_ext back to the client extension, defeating the
    # library-level rename. The handler deny-list only arrives in 2.27/2.28.
    for module in (cve_2019_19576, cve_2019_19634):
        result = module.check("https://target.test", plugins=K2_211)
        assert result.status == "LIKELY_VULNERABLE"


def test_k2_fixed_releases_are_patched_per_cve():
    assert cve_2019_19576.check("https://target.test", plugins=K2_227).status == "PATCHED"
    assert cve_2019_19634.check("https://target.test", plugins=K2_227).status == "LIKELY_VULNERABLE"
    for module in (cve_2019_19576, cve_2019_19634):
        assert module.check("https://target.test", plugins=K2_228).status == "PATCHED"


def test_k2_280_lab_version_is_affected():
    for module in (cve_2019_19576, cve_2019_19634):
        result = module.check("https://target.test", plugins=K2_280)
        assert result.status == "LIKELY_VULNERABLE"


def test_k2_wrappers_accept_cli_joomla_version_positional_argument():
    for module in (cve_2019_19576, cve_2019_19634):
        result = module.check(
            "https://target.test",
            "3.4.8",
            run_exploit_check=False,
            plugins=K2_268,
        )
        assert result.status == "LIKELY_VULNERABLE"
