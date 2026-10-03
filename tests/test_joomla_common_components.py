import unittest
from types import SimpleNamespace
from unittest.mock import patch

from proofcms.core.models import PluginInfo
from proofcms.detectors import joomla


class TestCommonJoomlaComponents(unittest.TestCase):
    @staticmethod
    def _response(status=200, body=""):
        return {"status": status, "body": body, "body_hash": "test"}

    def test_akeeba_backup_manifest_extracts_version(self):
        manifest = """<?xml version="1.0"?>
        <extension type="component"><name>com_akeebabackup</name><version>10.1.2</version></extension>
        """
        with (
            patch.object(joomla, "fetch_url", return_value=self._response(body=manifest)) as fetch,
            patch.object(joomla, "is_baseline_match", return_value=False),
        ):
            result = joomla.detect_common_component("https://example.test", "akeebabackup", 2)
        self.assertTrue(result.found)
        self.assertEqual(result.version, "10.1.2")
        self.assertIn("com_akeebabackup/akeebabackup.xml", fetch.call_args.args[0])

    def test_jsitemap_manifest_extracts_version(self):
        manifest = """<?xml version="1.0"?>
        <extension type="component"><name>JSitemap</name><version>4.31.6</version></extension>
        """
        with (
            patch.object(joomla, "fetch_url", return_value=self._response(body=manifest)),
            patch.object(joomla, "is_baseline_match", return_value=False),
        ):
            result = joomla.detect_common_component("https://example.test", "jsitemap", 2)
        self.assertTrue(result.found)
        self.assertEqual(result.version, "4.31.6")

    def test_nrframework_manifest_extracts_version(self):
        manifest = """<?xml version="1.0"?>
        <extension type="plugin"><name>plg_system_nrframework</name><version>6.0.37</version></extension>
        """
        with (
            patch.object(joomla, "fetch_url", return_value=self._response(body=manifest)),
            patch.object(joomla, "is_baseline_match", return_value=False),
        ):
            result = joomla.detect_common_component("https://example.test", "nrframework", 2)
        self.assertTrue(result.found)
        self.assertEqual(result.version, "6.0.37")

    def test_mailchimp_manifest_extracts_version(self):
        manifest = """<?xml version="1.0"?>
        <extension type="plugin"><name>MailChimp Auto-Subscribe</name><version>5.1.1</version></extension>
        """
        with (
            patch.object(joomla, "fetch_url", return_value=self._response(body=manifest)),
            patch.object(joomla, "is_baseline_match", return_value=False),
        ):
            result = joomla.detect_common_component(
                "https://example.test", "mailchimp_auto_subscribe", 2
            )
        self.assertTrue(result.found)
        self.assertEqual(result.version, "5.1.1")

    def test_generic_200_page_is_not_a_component(self):
        with (
            patch.object(joomla, "fetch_url", return_value=self._response(body="generic home page")),
            patch.object(joomla, "is_baseline_match", return_value=False),
        ):
            result = joomla.detect_common_component("https://example.test", "jsitemap", 2)
        self.assertFalse(result.found)

    def test_common_inventory_runs_without_cve_dependency(self):
        args = SimpleNamespace(timeout=2, proxy=None, concurrency=1)
        absent = PluginInfo(False, None, "not-detected")
        with patch.object(joomla, "detect_common_component", return_value=absent) as detector:
            results = joomla.detect_plugins(
                "https://example.test", args, required_plugins=set(), concurrency=1
            )
        self.assertEqual(detector.call_count, len(joomla.COMMON_COMPONENTS))
        self.assertTrue(set(joomla.COMMON_COMPONENTS).issubset(results))
        self.assertTrue(all(results[key]["source"] == "not-detected" for key in joomla.COMMON_COMPONENTS))

    def test_acymailing_legacy_manifest_detects_version_and_enterprise_edition(self):
        manifest = """<extension type="component">
        <name>AcyMailing Enterprise</name><version>5.8.1</version></extension>"""
        with (
            patch.object(joomla, "fetch_url", return_value=self._response(body=manifest)),
            patch.object(joomla, "is_baseline_match", return_value=False),
        ):
            result = joomla.detect_common_component("https://example.test", "acymailing", 2)
        self.assertTrue(result.found)
        self.assertEqual(result.version, "5.8.1")
        self.assertEqual(result.edition, "enterprise")

    def test_requested_third_party_system_plugins_have_manifest_probes(self):
        expected = {
            "akeeba_update_check",
            "backup_on_update",
            "convertforms_uploaded_files_cleaner",
            "dropfiles",
            "k2",
            "login_popup",
            "rsform_delete_submissions",
            "rsfp_campaignmonitor",
            "rsfp_google",
            "rsfp_google_calendar",
            "rsfp_google_sheets",
            "rsfp_hcaptcha",
            "rsfp_ideal",
            "rsfp_legacy_layouts",
            "rsfp_pdf",
            "rsfp_registration",
            "smartslider3",
            "sppagebuilder_pro_updater",
            "tassos_geoip",
        }
        self.assertTrue(expected.issubset(joomla.COMMON_COMPONENTS))
        for key in expected:
            self.assertTrue(joomla.COMMON_COMPONENTS[key]["manifests"])


if __name__ == "__main__":
    unittest.main()
