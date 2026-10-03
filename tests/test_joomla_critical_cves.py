import unittest
from unittest.mock import patch

from proofcms.detectors import joomla
from proofcms.modules.joomla import (
    cve_2015_7857,
    cve_2016_8869,
    cve_2016_8870,
    cve_2017_8917,
    cve_2018_15882,
    cve_2025_26854,
    cve_2026_61424,
    cve_2026_73373,
    cve_2026_90915,
    cve_2026_92222,
)


class TestJoomlaCriticalVersionPolicies(unittest.TestCase):
    def test_core_boundaries(self):
        cases = (
            (cve_2017_8917, "3.6.5", "NOT_AFFECTED"),
            (cve_2015_7857, "3.1.6", "NOT_AFFECTED"),
            (cve_2015_7857, "3.4.4", "LIKELY_VULNERABLE"),
            (cve_2015_7857, "3.4.5", "PATCHED"),
            (cve_2016_8869, "3.4.3", "NOT_AFFECTED"),
            (cve_2016_8869, "3.4.4", "LIKELY_VULNERABLE"),
            (cve_2016_8869, "3.6.4", "PATCHED"),
            (cve_2016_8870, "3.6.3", "LIKELY_VULNERABLE"),
            (cve_2016_8870, "3.6.4", "PATCHED"),
            (cve_2017_8917, "3.7.0", "LIKELY_VULNERABLE"),
            (cve_2017_8917, "3.7.1", "PATCHED"),
            (cve_2018_15882, "3.8.11", "LIKELY_VULNERABLE"),
            (cve_2018_15882, "3.8.12", "PATCHED"),
            (cve_2026_73373, "5.4.7", "LIKELY_VULNERABLE"),
            (cve_2026_73373, "5.4.8", "PATCHED"),
            (cve_2026_73373, "6.1.2", "LIKELY_VULNERABLE"),
            (cve_2026_73373, "6.1.3", "PATCHED"),
            (cve_2026_90915, "3.10.12", "NOT_AFFECTED"),
            (cve_2026_90915, "5.4.8", "LIKELY_VULNERABLE"),
            (cve_2026_90915, "5.4.9", "PATCHED"),
            (cve_2026_90915, "6.1.3", "LIKELY_VULNERABLE"),
            (cve_2026_90915, "6.1.4", "PATCHED"),
            (cve_2026_92222, "2.5.28", "NOT_AFFECTED"),
            (cve_2026_92222, "3.10.12", "LIKELY_VULNERABLE"),
            (cve_2026_92222, "5.4.9", "PATCHED"),
            (cve_2026_92222, "6.1.3", "LIKELY_VULNERABLE"),
            (cve_2026_92222, "6.1.4", "PATCHED"),
        )
        for module, version, expected in cases:
            with self.subTest(cve=module.CVE_ID, version=version):
                self.assertEqual(module.classify_version(version), expected)

    def test_extension_boundaries(self):
        cases = (
            (cve_2025_26854, "0.9.9", "NOT_AFFECTED"),
            (cve_2025_26854, "1.2.4.0011", "LIKELY_VULNERABLE"),
            (cve_2025_26854, "1.2.5", "NOT_AFFECTED"),
            (cve_2026_61424, "3.11.1", "LIKELY_VULNERABLE"),
            (cve_2026_61424, "3.11.2", "PATCHED"),
        )
        for module, version, expected in cases:
            with self.subTest(cve=module.CVE_ID, version=version):
                self.assertEqual(module.classify_version(version), expected)

    def test_standard_checks_are_passive(self):
        core = cve_2026_73373.check("https://target.test", joomla_version="5.4.7")
        extension = cve_2026_61424.check(
            "https://target.test",
            plugins={"djclassifieds": {"found": True, "version": "3.11.1"}},
            run_exploit_check=True,
        )
        self.assertEqual(core.status, "LIKELY_VULNERABLE")
        self.assertEqual(extension.status, "LIKELY_VULNERABLE")
        self.assertTrue(core.exploit_available)
        self.assertFalse(extension.exploit_available)

    def test_phar_stub_payload_is_inert(self):
        payload = cve_2018_15882.build_inert_phar_stub("PROOFCMS_TEST")
        self.assertIn(b"GIF89a", payload)
        self.assertIn(b"__HALT_COMPILER()", payload)
        self.assertNotIn(b"system(", payload)
        self.assertNotIn(b"eval(", payload)

    def test_phar_upload_confirmation(self):
        proof = {
            "accepted": True,
            "proof_url": "https://target.test/images/proofcms.gif",
            "uploaded_filename": "images/proofcms.gif",
            "attempts": [],
        }
        with patch.object(cve_2018_15882, "probe_upload", return_value=proof):
            result = cve_2018_15882.check(
                "https://target.test",
                "3.8.11",
                run_exploit_check=True,
                exploit_mode="aggressive",
            )
        self.assertEqual(result.status, "VULNERABLE_UPLOAD_ONLY")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertTrue(result.exploit_ran)


class TestJoomlaCriticalExtensionDiscovery(unittest.TestCase):
    @staticmethod
    def _response(status=200, body=""):
        return {"status": status, "body": body, "body_hash": "test"}

    def test_articles_good_search_manifest(self):
        manifest = """<extension type="module">
        <name>mod_articles_good_search</name><version>1.2.4.0011</version></extension>"""
        with (
            patch.object(joomla, "fetch_url", return_value=self._response(body=manifest)),
            patch.object(joomla, "is_baseline_match", return_value=False),
        ):
            result = joomla.detect_common_component("https://example.test", "articles_good_search", 2)
        self.assertTrue(result.found)
        self.assertEqual(result.version, "1.2.4.0011")

    def test_djclassifieds_manifest(self):
        manifest = """<extension type="component">
        <name>com_djclassifieds</name><version>3.11.1</version></extension>"""
        with (
            patch.object(joomla, "fetch_url", return_value=self._response(body=manifest)),
            patch.object(joomla, "is_baseline_match", return_value=False),
        ):
            result = joomla.detect_common_component("https://example.test", "djclassifieds", 2)
        self.assertTrue(result.found)
        self.assertEqual(result.version, "3.11.1")

    def test_generic_200_does_not_detect_new_extensions(self):
        with (
            patch.object(joomla, "fetch_url", return_value=self._response(body="generic homepage")),
            patch.object(joomla, "is_baseline_match", return_value=False),
        ):
            for component in ("articles_good_search", "djclassifieds"):
                with self.subTest(component=component):
                    result = joomla.detect_common_component("https://example.test", component, 2)
                    self.assertFalse(result.found)


if __name__ == "__main__":
    unittest.main()
