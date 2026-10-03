from unittest.mock import patch

from proofcms.modules.joomla import (
    cve_2018_15882,
    cve_2026_48907,
    cve_2026_49049,
)
from proofcms.modules.joomla.joomla_media_probe import (
    discover_media_form,
    probe_media_upload,
)

FORM = """
<form action="https://target.test/inicio/index.php?option=com_media&amp;task=file.upload&amp;token_a=1"
      method="post" enctype="multipart/form-data">
  <input type="hidden" name="folder" value="images">
  <input type="file" name="Filedata[]" multiple>
</form>
"""


def test_discovers_exact_media_action_and_array_file_field():
    class Session:
        base_url = "https://target.test/inicio"

        def get(self, path):
            return {
                "status": 200,
                "body": FORM,
                "redirected": False,
                "final_url": "https://target.test/inicio/index.php?option=com_media&view=images",
            }

    form = discover_media_form(Session())
    assert form["file_field"] == "Filedata[]"
    assert "task=file.upload" in form["action"]
    assert "token_a=1" in form["action"]


def test_media_probe_requires_marker_readback_and_negative_control():
    class Session:
        def __init__(self, **kwargs):
            self.base_url = "https://target.test/inicio"

        def get(self, path):
            if "view=images" in path:
                return {
                    "status": 200,
                    "body": FORM,
                    "redirected": False,
                    "final_url": "https://target.test/inicio/index.php?option=com_media&view=images",
                }
            if "proofcms-missing" in path:
                return {"status": 404, "body": "missing", "body_hash": "missing", "redirected": False}
            return {"status": 200, "body": "UNIQUE", "body_hash": "proof", "redirected": False}

        def post(self, url, fields, files):
            assert "format=json" not in url
            assert "Filedata[]" in files
            return {"status": 303, "body": "", "redirected": True}

    with patch("proofcms.modules.joomla.joomla_media_probe.HttpSession", Session):
        result = probe_media_upload(
            "https://target.test/inicio",
            filename="proof.txt",
            payload=b"UNIQUE",
            marker="UNIQUE",
            content_type="text/plain",
        )
    assert result["accepted"] is True
    assert result["file_field"] == "Filedata[]"


def test_phar_probe_reports_exposed_surface_when_payload_is_rejected():
    with patch.object(
        cve_2018_15882,
        "probe_media_upload",
        return_value={
            "surface_found": True,
            "accepted": False,
            "write_reported": True,
            "attempts": ["upload=303,proof=404"],
        },
    ):
        result = cve_2018_15882.check(
            "https://target.test/inicio",
            "3.4.8",
            run_exploit_check=True,
            exploit_mode="aggressive",
        )
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["upload_surface_found"] is True
    assert "live anonymous com_media upload form" in result.detail


def test_helix3_probe_is_skipped_when_component_is_not_detected():
    with patch.object(cve_2026_49049, "run_safe_probe") as probe:
        result = cve_2026_49049.check(
            "https://target.test",
            run_exploit_check=True,
            exploit_mode="safe",
            plugins={"helix3": {"found": False}},
        )
    probe.assert_not_called()
    assert result.status == "NOT_DETECTED"
    assert result.uploaded_filename is None


def test_jce_generic_200_does_not_create_phantom_cleanup_file():
    passive = cve_2026_48907.Finding(
        cve=cve_2026_48907.CVE_ID,
        name=cve_2026_48907.NAME,
        status="LIKELY_VULNERABLE",
        confidence="HIGH",
        component=cve_2026_48907.COMPONENT,
        component_version="2.5.8",
        affected_rule=cve_2026_48907.AFFECTED_RULE,
    )
    with (
        patch.object(cve_2026_48907, "passive_check", return_value=passive),
        patch.object(cve_2026_48907, "_extract_csrf", return_value=("a" * 32, "/login", [])),
        patch.object(
            cve_2026_48907.HttpSession,
            "post",
            return_value={"status": 200, "body": "", "redirected": False},
        ),
    ):
        result = cve_2026_48907.run_exploit("https://target.test", "3.4.8")
    assert result.status == "NOT_CONFIRMED"
    assert result.uploaded_filename is None
    assert result.evidence["handler_reached"] is False


def test_jce_redirect_is_reported_as_externally_blocked():
    passive = cve_2026_48907.Finding(
        cve=cve_2026_48907.CVE_ID,
        name=cve_2026_48907.NAME,
        status="LIKELY_VULNERABLE",
        confidence="HIGH",
        component=cve_2026_48907.COMPONENT,
        component_version="2.5.15",
        affected_rule=cve_2026_48907.AFFECTED_RULE,
    )
    with (
        patch.object(cve_2026_48907, "passive_check", return_value=passive),
        patch.object(cve_2026_48907, "_extract_csrf", return_value=("a" * 32, "/", [])),
        patch.object(
            cve_2026_48907.HttpSession,
            "post",
            return_value={"status": 200, "body": "homepage", "redirected": True},
        ),
    ):
        result = cve_2026_48907.run_exploit("https://target.test", "3.4.8")

    assert result.status == "BLOCKED_EXTERNAL"
    assert "external validation is blocked" in result.detail
    assert result.uploaded_filename is None
