import base64
import unittest
from unittest.mock import patch

from proofcms.modules.joomla import cve_2024_40744, cve_2026_73373
from proofcms.modules.joomla.convertforms_probe import _form_upload_fields, _uploaded_basename


class TestConvertFormsUploadDiscovery(unittest.TestCase):
    def test_extracts_real_form_field_and_token(self):
        html = """
        <form id="cf12">
          <input type="hidden" name="cf[form_id]" value="12">
          <input type="hidden" name="0123456789abcdef0123456789abcdef" value="1">
          <div data-key="7" class="dropzone cfupload"></div>
        </form>
        """
        self.assertEqual(
            _form_upload_fields(html),
            [("12", "7", "0123456789abcdef0123456789abcdef")],
        )

    def test_decodes_randomized_server_filename(self):
        encoded = base64.b64encode(b"/var/www/html/tmp/cf_123_proof.php").decode()
        self.assertEqual(
            _uploaded_basename(f'noise {{"file":"{encoded}"}} noise'),
            "cf_123_proof.php",
        )


class TestConvertFormsSafeProof(unittest.TestCase):
    def test_runtime_marker_confirms_execution_and_self_cleanup(self):
        proof = {
            "accepted": True,
            "response": {"status": 200, "body": "GIF89aPROOFCMS_CF_MARKERABC_144"},
            "proof_url": "https://target.test/tmp/cf_proof.php",
            "uploaded_filename": "cf_proof.php",
        }
        plugins = {"convertforms": {"found": True, "version": "3.2.12", "source": "test"}}
        with (
            patch.object(cve_2024_40744, "rand_str", side_effect=["MARKERABC", "FILEABCD"]),
            patch.object(cve_2024_40744, "probe_upload", return_value=proof),
        ):
            result = cve_2024_40744.check(
                "https://target.test",
                plugins=plugins,
                run_exploit_check=True,
                exploit_mode="safe",
            )
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertTrue(result.exploit_ran)
        self.assertEqual(result.proof_url, proof["proof_url"])

    def test_accepted_nonexecuting_php_reports_upload_only(self):
        proof = {
            "accepted": True,
            "response": {"status": 200, "body": "GIF89a<?php echo 'marker'; ?>"},
            "proof_url": "https://target.test/tmp/cf_proof.php",
            "uploaded_filename": "cf_proof.php",
        }
        plugins = {"convertforms": {"found": True, "version": "3.2.12", "source": "test"}}
        with patch.object(cve_2024_40744, "probe_upload", return_value=proof):
            result = cve_2024_40744.run_safe_probe("https://target.test", plugins=plugins)
        self.assertEqual(result.status, "VULNERABLE_UPLOAD_ONLY")
        self.assertEqual(result.confidence, "CONFIRMED")


class TestShtmlSafeProof(unittest.TestCase):
    def test_ssi_execution_marker_confirms_vulnerability(self):
        proof = {
            "accepted": True,
            "response": {"status": 200, "body": "GIF89a PROOFCMS_SHTML_MARKERABC_EXEC"},
            "proof_url": "https://target.test/tmp/proof.shtml",
            "uploaded_filename": "proof.shtml",
        }
        with (
            patch.object(cve_2026_73373, "rand_str", side_effect=["MARKERABC", "FILEABCD"]),
            patch.object(cve_2026_73373, "probe_upload", return_value=proof),
        ):
            result = cve_2026_73373.check(
                "https://target.test",
                "3.9.10",
                run_exploit_check=True,
                exploit_mode="safe",
            )
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")

    def test_raw_shtml_reports_upload_only(self):
        proof = {
            "accepted": True,
            "response": {"status": 200, "body": 'GIF89a marker <!--#exec cmd="printf marker" -->'},
            "proof_url": "https://target.test/tmp/proof.shtml",
            "uploaded_filename": "proof.shtml",
        }
        with patch.object(cve_2026_73373, "probe_upload", return_value=proof):
            result = cve_2026_73373.run_safe_probe("https://target.test", "3.9.10")
        self.assertEqual(result.status, "VULNERABLE_UPLOAD_ONLY")
        self.assertEqual(result.confidence, "CONFIRMED")


if __name__ == "__main__":
    unittest.main()
