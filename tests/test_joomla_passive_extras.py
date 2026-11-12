"""Version-gate tests for the passive-only Joomla extras (72531 / 14596)."""
import unittest

from proofcms.modules.joomla import cve_2017_14596, cve_2026_72531


class TestPassiveExtras(unittest.TestCase):
    def test_72531_gates(self):
        self.assertEqual(cve_2026_72531.classify_version("5.4.7"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_72531.classify_version("5.4.8"), "PATCHED")
        self.assertEqual(cve_2026_72531.classify_version("6.1.2"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2026_72531.classify_version("6.1.3"), "PATCHED")
        self.assertEqual(cve_2026_72531.classify_version("3.10.12"), "NOT_AFFECTED")
        self.assertEqual(cve_2026_72531.classify_version(None), "INCONCLUSIVE")

    def test_14596_gates(self):
        self.assertEqual(cve_2017_14596.classify_version("3.7.5"), "LIKELY_VULNERABLE")
        self.assertEqual(cve_2017_14596.classify_version("3.8.0"), "PATCHED")
        self.assertEqual(cve_2017_14596.classify_version("3.10.12"), "PATCHED")
        self.assertEqual(cve_2017_14596.classify_version(None), "INCONCLUSIVE")

    def test_metadata_types(self):
        self.assertEqual(cve_2026_72531.metadata()["vulnerability_type"], "Improper Access Control")
        self.assertEqual(cve_2017_14596.metadata()["vulnerability_type"], "Information Disclosure")


if __name__ == "__main__":
    unittest.main()
