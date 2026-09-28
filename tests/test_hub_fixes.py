import json
import re
import unittest
from unittest.mock import MagicMock, patch

from proofcms import cli
from proofcms.core import (
    generate_php_math_payload,
    normalize_version_string,
    verify_php_execution,
    version_in_specifier,
    version_lt,
    version_lte,
)
from proofcms.modules.joomla import (
    cve_2010_4166,
    cve_2026_48907,
    cve_2026_48908,
    cve_2026_49049,
    cve_2026_56290,
    cve_2026_56291,
    cve_2026_57827,
    cve_2026_57830,
)


class TestPhpExecutionProof(unittest.TestCase):
    """Item 1: Ensure static PHP source code leakage is NEVER confused with PHP execution."""

    def test_math_payload_generation(self):
        code, product = generate_php_math_payload()
        self.assertIn("<?php", code)
        self.assertIn("JVH_MATH_", code)
        self.assertTrue(product.isdigit())

    def test_verify_genuine_execution(self):
        _, product = generate_php_math_payload()
        executed_body = f"Some header output\nJVH_MATH_{product}_END\nFooter"
        is_exec, is_leak = verify_php_execution(executed_body, product)
        self.assertTrue(is_exec)
        self.assertFalse(is_leak)

    def test_verify_rejects_source_leakage_with_marker(self):
        payload_code, product = generate_php_math_payload()
        # Server literally returned the PHP source code file
        is_exec, is_leak = verify_php_execution(payload_code, product)
        self.assertFalse(is_exec, "PHP source leak must not be treated as execution!")
        self.assertTrue(is_leak, "Must detect source leak")

    def test_verify_rejects_short_tags(self):
        body = "<?= 123 ?> JVH_MATH_99999_END"
        is_exec, is_leak = verify_php_execution(body, "99999")
        self.assertFalse(is_exec)
        self.assertTrue(is_leak)

    def test_jce_source_leakage_reports_upload_only(self):
        """CVE-2026-48907: Leaked PHP source should report VULNERABLE_UPLOAD_ONLY, not VULNERABLE."""
        fake_passive = cve_2026_48907.CVECheckResult(
            cve=cve_2026_48907.CVE_ID,
            name=cve_2026_48907.NAME,
            status="LIKELY_VULNERABLE",
            confidence="HIGH",
            component_version="2.9.90",
            detail="Vulnerable version detected.",
        )
        with patch.object(cve_2026_48907, "passive_check", return_value=fake_passive), \
             patch.object(cve_2026_48907, "_extract_csrf", return_value=("csrf_token", "/", ["/"])), \
             patch.object(cve_2026_48907.HttpSession, "post", return_value={"status": 200, "body": "OK"}), \
             patch.object(cve_2026_48907.HttpSession, "get", return_value={"status": 200, "body": "<?php echo 'source'; ?>"}), \
             patch("time.sleep"):
            result = cve_2026_48907.run_exploit("http://target", joomla_version="3.9.0")
            self.assertEqual(result.status, "VULNERABLE_UPLOAD_ONLY")


class TestVersionComparison(unittest.TestCase):
    """Item 7: Test standardized PEP 440 version comparisons."""

    def test_version_normalization(self):
        self.assertEqual(normalize_version_string("3.9.27-rc1"), "3.9.27rc1")
        self.assertEqual(normalize_version_string("2.5.0-beta2"), "2.5.0b2")
        self.assertEqual(normalize_version_string("1.5.21v1"), "1.5.21")

    def test_version_ordering(self):
        self.assertTrue(version_lt("3.4.5", "3.4.6"))
        self.assertTrue(version_lt("3.4.6-rc1", "3.4.6"))
        self.assertFalse(version_lt("3.4.6", "3.4.6"))
        self.assertTrue(version_lte("3.4.6", "3.4.6"))
        self.assertTrue(version_in_specifier("1.5.20", ">=1.5.0,<=1.5.21"))
        self.assertFalse(version_in_specifier("1.5.22", ">=1.5.0,<=1.5.21"))


class TestNativeJoomlaScanner(unittest.TestCase):
    def test_native_scanner_honors_proxy(self):
        with patch("proofcms.detectors.joomla.fetch_url") as mock_fetch:
            mock_fetch.return_value = {"status": 404, "body": "", "body_hash": "missing"}
            info = cli.scan_joomla("http://target", 10, proxy="http://127.0.0.1:8080")
        self.assertFalse(info.detected)
        self.assertIsNone(info.version)
        self.assertEqual(info.source, "native")
        self.assertTrue(all(call.kwargs["proxy"] == "http://127.0.0.1:8080" for call in mock_fetch.call_args_list))


class TestBaselineAndFalsePositives(unittest.TestCase):
    """Item 5: Blanket-403 and home redirects must not trigger false positives."""

    def test_is_baseline_match_blanket_403(self):
        baseline = {
            "status": 403,
            "blanket_403": True,
            "redirected_to_root": False,
            "body_hash": "dummyhash",
            "target_root": "http://target",
        }
        probe_resp = {"status": 403, "body_hash": "otherhash", "redirected": False}
        self.assertTrue(cli.is_baseline_match(probe_resp, baseline))

    def test_is_baseline_match_redirect_to_root(self):
        baseline = {
            "status": 200,
            "blanket_403": False,
            "redirected_to_root": True,
            "body_hash": "hash1",
            "target_root": "http://target",
        }
        probe_resp = {
            "status": 200,
            "final_url": "http://target/",
            "redirected": True,
            "body_hash": "hash2",
        }
        self.assertTrue(cli.is_baseline_match(probe_resp, baseline))

    def test_detect_wordpress_rejects_blanket_403(self):
        baseline = {"status": 403, "blanket_403": True, "target_root": "http://target"}
        with patch("proofcms.detectors.wordpress.fetch_url") as mock_fetch:
            # Returns 403 for /wp-admin/
            mock_fetch.return_value = {
                "status": 403,
                "body": "Access Denied",
                "body_hash": "abc",
                "final_url": "http://target/wp-admin/",
                "redirected": False,
            }
            res = cli.detect_wordpress("http://target", timeout=5, baseline=baseline)
            self.assertFalse(res.detected, "Blanket 403 must not detect WordPress!")

    def test_detect_wordpress_does_not_treat_dependency_version_as_core(self):
        response = {
            "status": 200,
            "body": (
                '<script src="/wp-includes/js/jquery/ui/core.min.js?ver=1.13.8"></script>'
                '<script src="/wp-includes/js/wp-emoji-release.min.js?ver=7.0.2"></script>'
            ),
            "body_hash": "homepage",
            "final_url": "http://target/",
            "redirected": False,
        }
        with patch("proofcms.detectors.wordpress.fetch_url", return_value=response):
            res = cli.detect_wordpress("http://target", timeout=5)

        self.assertTrue(res.detected)
        self.assertEqual(res.version, "7.0.2")


class TestJoomlaXmlManifestValidation(unittest.TestCase):
    """Item 6: Generic XMLs with <version> must be rejected by fallback Joomla detector."""

    def test_rejects_rss_or_sitemap(self):
        rss_body = "<rss version='2.0'><channel><version>5.4.1</version></channel></rss>"
        self.assertFalse(cli.validate_joomla_manifest(rss_body, "/feed.xml"))

        custom_xml = "<response><status>ok</status><version>3.9.0</version></response>"
        self.assertFalse(cli.validate_joomla_manifest(custom_xml, "/api.xml"))

    def test_accepts_authentic_joomla_manifest(self):
        joomla_manifest = """<?xml version="1.0" encoding="utf-8"?>
        <extension version="3.1" type="file" method="upgrade">
            <name>files_joomla</name>
            <author>Joomla! Project</author>
            <version>3.9.27</version>
        </extension>"""
        self.assertTrue(
            cli.validate_joomla_manifest(
                joomla_manifest,
                "/administrator/manifests/files/joomla.xml",
            )
        )


class TestModuleErrorIsolationAndSchema(unittest.TestCase):
    """Item 3: Individual module failure or malformed schema does not crash scan."""

    def test_helixultimate_schema_defensive(self):
        """CVE-2026-57830 should not raise AttributeError on unexpected JSON."""
        with patch.object(cve_2026_57830.HttpClient, "request") as mock_req, \
             patch("proofcms.modules.joomla.cve_2026_57830.find_anon_csrf_token", return_value=("dummy_token", "/")):
            mock_req.return_value = {
                "status": 200,
                "body": json.dumps(["unexpected", "list", "response"]),
            }
            result = cve_2026_57830.check(
                "http://target",
                joomla_version="3.9.0",
                run_exploit_check=True,
                plugins={"helixultimate": {"found": True, "version": "2.0.0", "source": "test"}},
            )
            self.assertIn(result.status, ("NOT_CONFIRMED", "PATCHED", "NOT_AFFECTED", "INCONCLUSIVE"))

    def test_main_loop_isolates_module_exception(self):
        """When a module raises an unhandled exception during scan, error is captured and scan completes."""
        with patch("proofcms.cli.load_targets", return_value=["http://target"]), \
             patch("proofcms.cli.probe_target_baseline", return_value={"status": 404, "blanket_403": False, "target_root": "http://target"}), \
             patch("proofcms.cli.detect_cms", return_value=cli.CMSInfo("joomla", True, "3.9.0", "test")), \
             patch("proofcms.cli.detect_plugins", return_value={}), \
             patch("proofcms.modules.joomla.cve_2010_4166.check", side_effect=RuntimeError("Simulated socket crash")), \
             patch("proofcms.modules.joomla.cve_2015_8562.check") as mock_cve2:
            mock_cve2.return_value = MagicMock(as_dict=lambda: {
                "cve": "CVE-2015-8562",
                "name": "Joomla RCE",
                "status": "NOT_AFFECTED",
                "confidence": "HIGH",
                "component": "Joomla core",
                "component_version": "3.9.0",
                "affected_rule": "",
                "detail": "",
                "action": "",
            })

            with patch("sys.argv", ["proofcms", "-u", "http://target", "--no-text-report", "--cve", "CVE-2010-4166,CVE-2015-8562"]):
                ret = cli.main()
                self.assertEqual(ret, 0, "Main must complete successfully even when a module crashes!")
                mock_cve2.assert_called_once()


class TestDifferentialSqli(unittest.TestCase):
    """Item 8: Differential verification against benign baseline in CVE-2010-4166."""

    def test_sqli_baseline_differential(self):
        with patch("proofcms.modules.joomla.cve_2010_4166.fetch") as mock_fetch:
            # If server ALWAYS outputs a generic syntax warning on every page
            mock_fetch.return_value = {
                "status": 200,
                "body": "Notice: SQL syntax error in /path/to/file.php",
            }
            # Both control and probe will have the same error -> diff is empty -> NOT_CONFIRMED (not VULNERABLE)
            result = cve_2010_4166.check("http://target", joomla_version="1.5.20", run_exploit_check=True)
            self.assertEqual(result.status, "NOT_CONFIRMED")
            self.assertIn("already present on the benign control request", result.detail)


class TestHelix3Cleanup(unittest.TestCase):
    """Item 9: Helix3 cleanup and restore tracking in CVE-2026-49049."""

    def test_helix3_restore_requested_and_verified(self):
        with patch("proofcms.modules.joomla.cve_2026_49049.request") as mock_req, patch("time.sleep"):
            state = {"call": 0, "marker": None}

            def fake_request(url, *args, **kwargs):
                if "option=com_ajax" in url:
                    data = kwargs.get("data", b"")
                    if isinstance(data, bytes):
                        data = data.decode("utf-8", errors="replace")
                    match = re.search(r"JVH_HELIX3_IMPORT_CONFIRMED_[A-Za-z0-9]+", data)
                    if match and not state["marker"]:
                        state["marker"] = match.group(0)
                    return {"status": 200, "body": '{"status":true}'}
                if "tmpl=comingsoon" in url:
                    state["call"] += 1
                    if state["call"] == 1:
                        return {"status": 200, "body": f"Page with {state['marker']}"}
                    return {"status": 200, "body": "Clean page without marker"}
                return {"status": 200, "body": '{"status":true}'}

            mock_req.side_effect = fake_request

            result = cve_2026_49049.run_visual_import_probe(
                "http://target",
                template_id=1,
                original_settings={"title": "old"},
            )
            self.assertEqual(result.status, "VULNERABLE")
            self.assertIn("restore_requested=True, restore_verified=True", result.detail)


class TestPageBuilderCkPolicy(unittest.TestCase):
    """User Adjustment 1: Page Builder CK affected range remains inconclusive/unknown."""

    def test_pagebuilderck_inconclusive_when_detected(self):
        result = cve_2026_56290.check(
            "http://target",
            joomla_version="3.9.0",
            run_exploit_check=False,
            plugins={"pagebuilderck": {"found": True, "version": "3.5.10", "source": "test"}},
        )
        self.assertEqual(result.status, "INCONCLUSIVE")
        self.assertIn("ambiguous", result.detail.lower())


class TestStatusSeparation(unittest.TestCase):
    """Item 4: Distinct states for NOT_DETECTED, INCONCLUSIVE, etc."""

    def test_not_detected_when_plugin_missing(self):
        result = cve_2026_48908.check(
            "http://target",
            joomla_version="3.9.0",
            run_exploit_check=False,
            plugins={"sppagebuilder": {"found": False, "version": None, "source": "not-detected"}},
        )
        self.assertEqual(result.status, "NOT_DETECTED")

    def test_status_color_palette(self):
        required_statuses = [
            "VULNERABLE",
            "VULNERABLE_UPLOAD_ONLY",
            "LIKELY_VULNERABLE",
            "INCONCLUSIVE",
            "DETECTED_VERSION_UNKNOWN",
            "PATCHED",
            "NOT_AFFECTED",
            "NOT_DETECTED",
            "NOT_CONFIRMED",
            "AGGRESSIVE_READY",
            "AGGRESSIVE_SENT",
            "NOT_JOOMLA",
            "ERROR",
        ]
        for st in required_statuses:
            color = cli.status_color(st)
            self.assertTrue(color.startswith("\033["), f"Color for {st} must be an ANSI escape code")
            self.assertNotEqual(color, "\033[97m", f"Status {st} should have an explicit assigned color")


class TestPhpExecutionProofAcrossModules(unittest.TestCase):
    """Ensure SP Page Builder, Balbooa Forms, and RSFiles never report VULNERABLE when source leaks."""

    def test_sppagebuilder_leakage_reports_upload_only(self):
        with patch("proofcms.modules.joomla.cve_2026_48908.request") as mock_req, patch("time.sleep"):
            # First call is upload (status 200), second call is proof (status 200 with raw PHP source)
            mock_req.side_effect = [
                {"status": 200, "body": "upload ok"},
                {"status": 200, "body": "<?php echo 'source code here'; ?>"},
            ]
            result = cve_2026_48908.run_aggressive_probe("http://target")
            self.assertEqual(result.status, "VULNERABLE_UPLOAD_ONLY")

    def test_baforms_leakage_reports_upload_only(self):
        with patch("proofcms.modules.joomla.cve_2026_56291.request") as mock_req, patch("time.sleep"):
            mock_req.side_effect = [
                {"status": 200, "body": "upload ok"},
                {"status": 200, "body": "<?php echo 'source code here'; ?>"},
            ]
            result = cve_2026_56291.run_aggressive_probe("http://target")
            self.assertEqual(result.status, "VULNERABLE_UPLOAD_ONLY")

    def test_rsfiles_leakage_reports_upload_only(self):
        with patch("proofcms.modules.joomla.cve_2026_57827.request") as mock_req, patch("time.sleep"):
            # Upload request
            # Proof request
            mock_req.side_effect = [
                {"status": 200, "body": "upload ok"},
                {"status": 200, "body": "<?php echo 'source code here'; ?>"},
                {"status": 404, "body": "Not found"},
                {"status": 404, "body": "Not found"},
                {"status": 404, "body": "Not found"},
                {"status": 404, "body": "Not found"},
            ]
            result = cve_2026_57827.run_aggressive_probe("http://target")
            self.assertEqual(result.status, "VULNERABLE_UPLOAD_ONLY")


if __name__ == "__main__":
    unittest.main()
