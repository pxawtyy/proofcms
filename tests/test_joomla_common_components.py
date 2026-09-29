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


if __name__ == "__main__":
    unittest.main()
