import unittest
from unittest.mock import patch

from proofcms.modules.wordpress import cve_2026_18781

PAGE_HTML = """
<html><body>
<input type="file" class="wpcf7-form-control wpcf7-drag-n-drop-file d-none"
       data-name="myfile" data-type="*" data-id="27" />
<script>var dnd_cf7_uploader = {"ajax_url":"/wp-admin/admin-ajax.php","ajax_nonce":"abc123def"};</script>
</body></html>
"""

DEFAULT_FORM_HTML = """
<html><body>
<input type="file" class="wpcf7-form-control wpcf7-drag-n-drop-file d-none"
       data-name="myfile" data-id="25" />
<script>var dnd_cf7_uploader = {"ajax_nonce":"abc123def"};</script>
</body></html>
"""

PHAR_SUCCESS = '{"success":true,"data":{"path":"proofcmsabc12345","file":"proofcmsabc12345.phar"}}'
HTACCESS_SUCCESS = '{"success":true,"data":{"path":"proofcmsabc12345","file":".htaccess"}}'
REJECTED = '{"success":false,"data":"Uploaded file is not allowed for file type"}'


class FakeSession:
    def __init__(self, *, executed=True, accepted=True, htaccess=True, vuln_form=True):
        self.executed = executed
        self.accepted = accepted
        self.htaccess = htaccess
        self.vuln_form = vuln_form
        self.uploads = []
        self.deletes = []

    def get(self, url, headers=None, timeout=None):
        if ".phar" in url:
            if self.executed:
                return {"status": 200, "body": "JVH_MATH_49_END"}
            return {"status": 200, "body": "<?php echo 'JVH_MATH_49_END'; ?>"}
        return {"status": 200, "body": PAGE_HTML if self.vuln_form else DEFAULT_FORM_HTML}

    def post_multipart(self, url, fields, files, headers=None, timeout=None):
        filename, content, content_type = next(iter(files.values()))
        self.uploads.append((filename, content, dict(fields)))
        if "pha\x01r" in filename:
            if not self.accepted:
                return {"status": 200, "body": REJECTED}
            return {"status": 200, "body": PHAR_SUCCESS}
        if "htacce\x01ss" in filename:
            if not self.htaccess:
                return {"status": 200, "body": REJECTED}
            return {"status": 200, "body": HTACCESS_SUCCESS}
        return {"status": 200, "body": '{"success":false}'}

    def post(self, url, data=None, fields=None, files=None, headers=None, timeout=None):
        self.deletes.append(dict(fields or {}))
        return {"status": 200, "body": '{"success":true,"data":"File Deleted!"}'}


class TestDragDropVersionPolicy(unittest.TestCase):
    def test_version_boundary(self):
        self.assertEqual(cve_2026_18781.classify_version("1.3.9.7"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_18781.classify_version("1.3.9.8"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_18781.classify_version("1.3.9.9"), "PATCHED")
        self.assertEqual(cve_2026_18781.classify_version("1.3.9.10"), "PATCHED")
        self.assertEqual(cve_2026_18781.classify_version(None), "DETECTED_VERSION_UNKNOWN")


class TestDragDropFormParsing(unittest.TestCase):
    def test_wildcard_form_is_parsed(self):
        form = cve_2026_18781.parse_dnd_form(PAGE_HTML)
        self.assertEqual(
            form,
            {"nonce": "abc123def", "field": "myfile", "form_id": "27"},
        )

    def test_default_form_is_not_wildcard(self):
        self.assertIsNone(cve_2026_18781.parse_dnd_form(DEFAULT_FORM_HTML))


class TestDragDropRceProbe(unittest.TestCase):
    def _run(self, fake):
        with (
            patch.object(cve_2026_18781, "HttpSession", return_value=fake),
            patch.object(
                cve_2026_18781,
                "generate_php_math_payload",
                return_value=("<?php echo 'JVH_MATH_49_END'; ?>", "49"),
            ),
        ):
            return cve_2026_18781.run_aggressive_probe(
                "https://target.test",
                form_url="https://target.test/contact/",
            )

    def test_executed_payload_is_confirmed_and_cleaned(self):
        fake = FakeSession()
        result = self._run(fake)
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertTrue(result.exploit_ran)
        self.assertTrue(result.cleanup_attempted)
        self.assertTrue(result.cleanup_verified)
        self.assertEqual(result.uploaded_filename, "proofcmsabc12345.phar")
        self.assertIn("proofcmsabc12345.phar", result.proof_url)
        # The executable payload is deleted through the plugin's delete action.
        self.assertEqual(fake.deletes[0]["action"], "dnd_codedropz_upload_delete")
        self.assertEqual(fake.deletes[0]["path"], "proofcmsabc12345/proofcmsabc12345.phar")
        # The .htaccess is written and then neutralised.
        filenames = [upload[0] for upload in fake.uploads]
        self.assertTrue(any("pha\x01r" in name for name in filenames))
        self.assertGreaterEqual(sum("htacce\x01ss" in name for name in filenames), 2)

    def test_source_only_is_upload_only(self):
        result = self._run(FakeSession(executed=False))
        self.assertEqual(result.status, "VULNERABLE_UPLOAD_ONLY")
        self.assertTrue(result.cleanup_verified)

    def test_rejected_phar_is_not_confirmed(self):
        result = self._run(FakeSession(accepted=False))
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertFalse(result.cleanup_attempted)

    def test_missing_wildcard_form_is_not_confirmed(self):
        result = self._run(FakeSession(vuln_form=False))
        self.assertEqual(result.status, "NOT_CONFIRMED")
        self.assertIn("filetypes:*", result.detail)

    def test_htaccess_failure_still_deletes_payload(self):
        result = self._run(FakeSession(htaccess=False, executed=False))
        self.assertEqual(result.status, "VULNERABLE_UPLOAD_ONLY")
        self.assertTrue(result.cleanup_attempted)
        # .phar removal still counts; no .htaccess was written.
        self.assertTrue(result.cleanup_verified)


class TestDragDropCheckGate(unittest.TestCase):
    def test_patched_version_skips_probe(self):
        plugins = {
            "drag-and-drop-multiple-file-upload-contact-form-7": {
                "found": True,
                "version": "1.3.9.9",
            }
        }
        with patch.object(cve_2026_18781, "run_aggressive_probe") as probe:
            result = cve_2026_18781.check(
                "https://target.test",
                run_exploit_check=True,
                exploit_mode="aggressive",
                plugins=plugins,
            )
        self.assertEqual(result.status, "PATCHED")
        self.assertFalse(result.exploit_ran)
        probe.assert_not_called()

    def test_vulnerable_version_runs_probe(self):
        plugins = {
            "drag-and-drop-multiple-file-upload-contact-form-7": {
                "found": True,
                "version": "1.3.9.8",
            }
        }
        with patch.object(cve_2026_18781, "run_aggressive_probe") as probe:
            probe.return_value.status = "VULNERABLE"
            result = cve_2026_18781.check(
                "https://target.test",
                run_exploit_check=True,
                exploit_mode="aggressive",
                aggressive_command="/?page_id=28",
                plugins=plugins,
            )
        probe.assert_called_once()
        self.assertEqual(result.status, "VULNERABLE")


if __name__ == "__main__":
    unittest.main()
