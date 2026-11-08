import json
import unittest
from unittest.mock import patch

from proofcms.modules.wordpress import cve_2020_25213

FILE_HASH = "l1_cHJvb2ZjbXMucGhw"
UPLOAD_JSON = json.dumps(
    {
        "added": [
            {
                "name": "proofcms.php",
                "hash": FILE_HASH,
                "url": "/wp-content/plugins/wp-file-manager/lib/php/../files/proofcms.php",
            }
        ]
    }
)


class FakeSession:
    def __init__(self, *, executed=True, accepted=True):
        self.executed = executed
        self.accepted = accepted
        self.cleanup_calls = []

    def post_multipart(self, url, fields, files, headers=None, timeout=None):
        if not self.accepted:
            return {"status": 200, "body": '{"error":["errUploadFile"]}'}
        return {"status": 200, "body": UPLOAD_JSON}

    def get(self, url, headers=None, timeout=None):
        if self.executed:
            return {"status": 200, "body": "JVH_MATH_49_END"}
        return {"status": 200, "body": "<?php echo 'JVH_MATH_49_END'; ?>"}

    def post(self, url, data=None, fields=None, files=None, headers=None, timeout=None):
        self.cleanup_calls.append(fields)
        return {"status": 200, "body": json.dumps({"removed": [FILE_HASH]})}


class TestWPFileManagerVersionPolicy(unittest.TestCase):
    def test_version_boundary(self):
        self.assertEqual(cve_2020_25213.classify_version("6.0"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2020_25213.classify_version("6.8"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2020_25213.classify_version("6.9"), "PATCHED")
        self.assertEqual(cve_2020_25213.classify_version("5.9"), "NOT_AFFECTED")
        self.assertEqual(cve_2020_25213.classify_version(None), "DETECTED_VERSION_UNKNOWN")


class TestWPFileManagerUploadProbe(unittest.TestCase):
    def test_upload_execution_is_confirmed_and_cleaned(self):
        fake = FakeSession()
        with (
            patch.object(cve_2020_25213, "HttpSession", return_value=fake),
            patch.object(
                cve_2020_25213,
                "generate_php_math_payload",
                return_value=("<?php echo 'JVH_MATH_49_END';", "49"),
            ),
        ):
            result = cve_2020_25213.run_aggressive_probe("https://target.test")
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertTrue(result.exploit_ran)
        self.assertTrue(result.cleanup_attempted)
        self.assertTrue(result.cleanup_verified)
        self.assertEqual(fake.cleanup_calls[0]["cmd"], "rm")
        self.assertEqual(fake.cleanup_calls[0]["targets[]"], FILE_HASH)

    def test_upload_source_only_is_not_execution(self):
        fake = FakeSession(executed=False)
        with (
            patch.object(cve_2020_25213, "HttpSession", return_value=fake),
            patch.object(
                cve_2020_25213,
                "generate_php_math_payload",
                return_value=("<?php echo 'JVH_MATH_49_END';", "49"),
            ),
        ):
            result = cve_2020_25213.run_aggressive_probe("https://target.test")
        self.assertEqual(result.status, "VULNERABLE_UPLOAD_ONLY")
        self.assertTrue(result.cleanup_verified)

    def test_rejected_upload_is_not_confirmed(self):
        fake = FakeSession(accepted=False)
        with patch.object(cve_2020_25213, "HttpSession", return_value=fake):
            result = cve_2020_25213.run_aggressive_probe("https://target.test")
        self.assertEqual(result.status, "NOT_CONFIRMED")


class TestWPFileManagerCheckGate(unittest.TestCase):
    def test_patched_version_skips_probe(self):
        plugins = {"wp-file-manager": {"found": True, "version": "6.9"}}
        with patch.object(cve_2020_25213, "run_aggressive_probe") as probe:
            result = cve_2020_25213.check(
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
