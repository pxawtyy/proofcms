import unittest
from unittest.mock import patch

from proofcms.modules.wordpress import cve_2020_35489

CF7_HTML = """
<div class="wpcf7" id="wpcf7-f21-o1">
  <form method="post" enctype="multipart/form-data">
    <input type="hidden" name="_wpcf7" value="21" />
    <input type="hidden" name="_wpcf7_version" value="5.3.1" />
    <input type="hidden" name="_wpcf7_unit_tag" value="wpcf7-f21-o1" />
    <input type="text" name="your-name" />
    <input type="file" name="upload-file" />
    <input type="submit" value="Send" />
  </form>
</div>
"""

REJECTED = '<form data-status="invalid">You are not allowed to upload files of this type.</form>'
ACCEPTED = '<form data-status="mail_failed">There was an error trying to send your message.</form>'


class FakeSession:
    def __init__(self, *, accept_bypass=True, form=True):
        self.accept_bypass = accept_bypass
        self.form = form
        self.submissions = []

    def get(self, url, headers=None, timeout=None):
        if not self.form:
            return {"status": 404, "body": ""}
        if url in ("https://target.test/", "https://target.test/contact/", "https://target.test/?page_id=22"):
            return {"status": 200, "body": CF7_HTML}
        return {"status": 404, "body": ""}

    def post_multipart(self, url, fields, files, headers=None, timeout=None):
        filename = next(iter(files.values()))[0]
        self.submissions.append((url, filename))
        if filename == cve_2020_35489.BASELINE_FILENAME:
            return {"status": 200, "body": REJECTED}
        if "\n" in filename:
            return {"status": 200, "body": ACCEPTED if self.accept_bypass else REJECTED}
        return {"status": 404, "body": ""}


class TestContactForm7VersionPolicy(unittest.TestCase):
    def test_version_boundary(self):
        self.assertEqual(cve_2020_35489.classify_version("5.3.1"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2020_35489.classify_version("5.3.2"), "PATCHED")
        self.assertEqual(cve_2020_35489.classify_version(None), "DETECTED_VERSION_UNKNOWN")


class TestContactForm7FormParsing(unittest.TestCase):
    def test_extracts_hidden_fields_file_field_and_fillable_inputs(self):
        form = cve_2020_35489.parse_cf7_form(CF7_HTML)
        self.assertIsNotNone(form)
        assert form is not None
        self.assertEqual(form["hidden"]["_wpcf7"], "21")
        self.assertEqual(form["hidden"]["_wpcf7_version"], "5.3.1")
        self.assertEqual(form["file_field"], "upload-file")
        self.assertEqual(form["fill"]["your-name"], "ProofCMS")


class TestContactForm7UploadProbe(unittest.TestCase):
    def test_control_character_bypass_is_confirmed(self):
        fake = FakeSession()
        with patch.object(cve_2020_35489, "HttpSession", return_value=fake):
            result = cve_2020_35489.run_aggressive_probe(
                "https://target.test",
                form_url="https://target.test/?page_id=22",
            )
        self.assertEqual(result.status, "VULNERABLE_UPLOAD_ONLY")
        self.assertEqual(result.confidence, "HIGH")
        assert result.evidence is not None
        self.assertEqual(result.evidence["baseline_result"], "REJECTED_FILE_TYPE")
        self.assertEqual(result.evidence["bypass_result"], "ACCEPTED")
        self.assertIn("\n", result.evidence["bypass_filename"])

    def test_rejected_bypass_is_not_confirmed(self):
        fake = FakeSession(accept_bypass=False)
        with patch.object(cve_2020_35489, "HttpSession", return_value=fake):
            result = cve_2020_35489.run_aggressive_probe(
                "https://target.test",
                form_url="https://target.test/?page_id=22",
            )
        self.assertEqual(result.status, "NOT_CONFIRMED")

    def test_missing_form_is_not_confirmed(self):
        fake = FakeSession(form=False)
        with patch.object(cve_2020_35489, "HttpSession", return_value=fake):
            result = cve_2020_35489.run_aggressive_probe(
                "https://target.test",
                form_url="https://target.test/?page_id=22",
            )
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertIn("No Contact Form 7 form", result.detail)


class TestContactForm7CheckGate(unittest.TestCase):
    def test_patched_version_skips_aggressive_probe(self):
        plugins = {"contact-form-7": {"found": True, "version": "5.3.2"}}
        with patch.object(cve_2020_35489, "run_aggressive_probe") as probe:
            result = cve_2020_35489.check(
                "https://target.test",
                run_exploit_check=True,
                exploit_mode="aggressive",
                plugins=plugins,
            )
        self.assertEqual(result.status, "PATCHED")
        self.assertFalse(result.exploit_ran)
        probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
