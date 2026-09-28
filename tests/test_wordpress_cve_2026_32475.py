import unittest
from unittest.mock import patch

from proofcms.modules.wordpress import cve_2026_32475 as module


class TestCVE202632475Policy(unittest.TestCase):
    def test_version_boundaries(self):
        self.assertEqual(module.classify_version("4.2.1"), "LIKELY_VULNERABLE")
        self.assertEqual(module.classify_version("4.2.2"), "PATCHED")
        self.assertEqual(module.classify_version(None), "DETECTED_VERSION_UNKNOWN")

    def test_plugin_detection_states(self):
        missing = module.passive_result({})
        unknown = module.passive_result({"elementor-pro": {"found": True, "version": None}})
        affected = module.passive_result({"elementor-pro": {"found": True, "version": "4.2.1"}})
        self.assertEqual(missing.status, "NOT_DETECTED")
        self.assertEqual(unknown.status, "DETECTED_VERSION_UNKNOWN")
        self.assertEqual(affected.status, "LIKELY_VULNERABLE")


class TestCVE202632475FormAndProbe(unittest.TestCase):
    HTML = """
    <form>
      <input name="post_id" value="42">
      <input name="form_id" value="abc123">
      <input type="file" name="form_fields[resume][]">
    </form>
    """

    def test_extracts_optional_upload_field(self):
        self.assertEqual(
            module.extract_form_data(self.HTML),
            {"post_id": "42", "form_id": "abc123", "field_id": "resume"},
        )
        self.assertIsNone(module.extract_form_data(self.HTML.replace(">\n    </form>", " required>\n    </form>")))

    def test_multipart_contains_empty_then_php_file_parts(self):
        content_type, body = module._multipart({}, "resume", "proofcms.php", b"<?php echo 1; ?>")
        self.assertIn("multipart/form-data; boundary=", content_type)
        self.assertEqual(body.count(b'name="form_fields[resume][]"'), 2)
        self.assertLess(body.index(b'filename=""'), body.index(b'filename="proofcms.php"'))

    def test_execution_marker_confirms_rce(self):
        upload = {"status": 200, "body": '{"success":true}', "headers": {}}
        proof = {"status": 200, "body": "JVH_MATH_408_END"}
        cleaned = {"status": 404, "body": ""}
        with (
            patch.object(
                module,
                "discover_form",
                return_value=("http://target/form", {"post_id": "42", "form_id": "abc", "field_id": "resume"}),
            ),
            patch.object(module, "_directory_php_names", side_effect=[set(), {"abcdef1234567.php"}]),
            patch.object(module, "generate_php_math_payload", return_value=("<?php $a=12;$b=34;echo 'JVH_MATH_'.($a*$b).'_END'; ?>", "408")),
            patch.object(module, "request", side_effect=[upload, proof, cleaned]),
        ):
            result = module.run_safe_probe("http://target")
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertIsNone(result.uploaded_filename)

    def test_accepted_upload_without_recoverable_name_is_upload_only(self):
        with (
            patch.object(
                module,
                "discover_form",
                return_value=("http://target/form", {"post_id": "42", "form_id": "abc", "field_id": "resume"}),
            ),
            patch.object(module, "_directory_php_names", side_effect=[set(), set()]),
            patch.object(module, "request", return_value={"status": 200, "body": '{"success":true}'}),
        ):
            result = module.run_safe_probe("http://target")
        self.assertEqual(result.status, "VULNERABLE_UPLOAD_ONLY")

    def test_patched_plugin_skips_probe(self):
        plugins = {"elementor-pro": {"found": True, "version": "4.2.2"}}
        with patch.object(module, "run_safe_probe") as probe:
            result = module.check("http://target", run_exploit_check=True, plugins=plugins)
        self.assertEqual(result.status, "PATCHED")
        probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
