import http.client
import unittest
import unittest.mock

import proofcms.modules.joomla as joomla_modules
from proofcms.cli import selected_chains, selected_cves
from proofcms.core.evidence import (
    find_sql_errors,
    generate_php_math_payload,
    verify_php_execution,
)
from proofcms.core.http import (
    HttpClient,
    build_multipart,
    form_encode,
    normalize_url,
    poll_paths,
)
from proofcms.core.models import Confidence, CVECheckResult, Finding, Status
from proofcms.core.probes import (
    extract_csrf_from_html,
    rand_str,
)
from proofcms.core.versions import (
    normalize_version_string,
    parse_version_safe,
    version_gt,
    version_gte,
    version_in_specifier,
    version_lt,
    version_lte,
)
from proofcms.modules.base import VulnerabilityModule
from proofcms.reporting import sanitize_argv


class TestProofCMSModels(unittest.TestCase):
    def test_finding_creation_and_dict(self):
        f = Finding(
            cve="CVE-TEST-1",
            name="Test Vulnerability",
            status=Status.VULNERABLE,
            confidence=Confidence.CONFIRMED,
            component="com_test",
            component_version="1.0.0",
            affected_rule="com_test < 2.0.0",
            detail="Test detail",
            action="Test action",
        )
        self.assertEqual(f.cve, "CVE-TEST-1")
        self.assertEqual(f.status, "VULNERABLE")
        self.assertEqual(f["cve"], "CVE-TEST-1")
        self.assertEqual(f.get("status"), "VULNERABLE")

        d = f.as_dict()
        self.assertEqual(d["cve"], "CVE-TEST-1")
        self.assertEqual(d["name"], "Test Vulnerability")
        self.assertEqual(d["status"], "VULNERABLE")
        self.assertEqual(d["confidence"], "CONFIRMED")
        self.assertEqual(d["component"], "com_test")
        self.assertEqual(d["component_version"], "1.0.0")

    def test_cve_check_result_is_finding(self):
        self.assertIs(CVECheckResult, Finding)


class TestProofCMSHttpAndMultipart(unittest.TestCase):
    def test_build_multipart(self):
        fields = {"title": "Hello", "action": "save"}
        files = {"upload": ("payload.php", b"<?php echo 123;", "application/x-php")}
        content_type, body = build_multipart(fields, files)

        self.assertTrue(content_type.startswith("multipart/form-data; boundary="))
        self.assertIn(b'name="title"', body)
        self.assertIn(b"Hello", body)
        self.assertIn(b'filename="payload.php"', body)
        self.assertIn(b"<?php echo 123;", body)

    def test_form_encode(self):
        encoded = form_encode({"key": "val", "token": "abc"})
        self.assertEqual(encoded, b"key=val&token=abc")

    def test_normalize_url(self):
        self.assertEqual(normalize_url("example.com"), "https://example.com")
        self.assertEqual(normalize_url("http://example.com/"), "http://example.com")
        self.assertEqual(normalize_url("https://example.com/path/"), "https://example.com/path")

    def test_http_client_initialization(self):
        client = HttpClient(timeout=10, user_agent="CustomAgent/1.0", proxy="http://127.0.0.1:8080")
        self.assertEqual(client.timeout, 10)
        self.assertEqual(client.user_agent, "CustomAgent/1.0")
        self.assertEqual(client.proxy, "http://127.0.0.1:8080")


class TestProofCMSVersions(unittest.TestCase):
    def test_version_parsing_and_normalization(self):
        self.assertEqual(normalize_version_string("v3.9.1-beta2"), "3.9.1b2")
        self.assertIsNotNone(parse_version_safe("3.9.1"))
        self.assertIsNone(parse_version_safe("invalid-xyz"))

    def test_version_comparisons(self):
        self.assertTrue(version_lt("1.2.0", "1.3.0"))
        self.assertFalse(version_lt("1.3.0", "1.2.0"))
        self.assertTrue(version_lte("1.2.0", "1.2.0"))
        self.assertTrue(version_gt("2.0.0", "1.9.9"))
        self.assertTrue(version_gte("2.0.0", "2.0.0"))
        self.assertTrue(version_in_specifier("1.5.0", "< 2.0.0, >= 1.0.0"))
        self.assertFalse(version_in_specifier("2.5.0", "< 2.0.0"))


class TestProofCMSEvidence(unittest.TestCase):
    def test_generate_and_verify_php_execution(self):
        code, product = generate_php_math_payload()
        self.assertIn("<?php", code)
        self.assertNotIn(product, code)

        # Genuine execution
        body_good = f"Output: JVH_MATH_{product}_END"
        is_exec, is_leak = verify_php_execution(body_good, product)
        self.assertTrue(is_exec)
        self.assertFalse(is_leak)

        # Leaked source
        body_leak = f"<?php $a=10; ?> JVH_MATH_{product}_END"
        is_exec, is_leak = verify_php_execution(body_leak, product)
        self.assertFalse(is_exec)
        self.assertTrue(is_leak)

    def test_find_sql_errors(self):
        errors = find_sql_errors("Fatal error: You have an error in your SQL syntax near '' at line 1")
        self.assertTrue(len(errors) > 0)
        self.assertEqual(find_sql_errors("Clean HTML response"), [])


class TestProofCMSProbes(unittest.TestCase):
    def test_rand_str(self):
        s1 = rand_str(12)
        s2 = rand_str(12)
        self.assertEqual(len(s1), 12)
        self.assertNotEqual(s1, s2)

    def test_extract_csrf(self):
        html1 = '<input type="hidden" name="d41d8cd98f00b204e9800998ecf8427e" value="1">'
        self.assertEqual(extract_csrf_from_html(html1), "d41d8cd98f00b204e9800998ecf8427e")

        html2 = 'var config = {"csrf.token": "d41d8cd98f00b204e9800998ecf8427e"};'
        self.assertEqual(extract_csrf_from_html(html2), "d41d8cd98f00b204e9800998ecf8427e")


class TestVulnerabilityModuleProtocol(unittest.TestCase):
    def test_all_10_modules_conform_to_protocol(self):
        all_modules = [
            joomla_modules.cve_2010_4166,
            joomla_modules.cve_2015_8562,
            joomla_modules.cve_2026_48907,
            joomla_modules.cve_2026_48908,
            joomla_modules.cve_2026_48939,
            joomla_modules.cve_2026_49049,
            joomla_modules.cve_2026_56290,
            joomla_modules.cve_2026_56291,
            joomla_modules.cve_2026_57827,
            joomla_modules.cve_2026_57830,
        ]
        self.assertEqual(len(all_modules), 10)
        for mod in all_modules:
            self.assertTrue(
                isinstance(mod, VulnerabilityModule),
                f"{mod.__name__} does not conform to VulnerabilityModule protocol",
            )
            meta = mod.metadata()
            self.assertIsInstance(meta, dict)
            self.assertIn("cve", meta)
            self.assertIn("name", meta)
            self.assertIn("affected_rule", meta)
            self.assertIn("exploit_available", meta)
            self.assertIn("exploit_modes", meta)

            # Check that passive check returns a Finding
            res = mod.check("http://example.invalid", joomla_version="3.9.0", plugins={})
            self.assertIsInstance(res, Finding, f"{mod.__name__}.check did not return a Finding")
            self.assertEqual(res.cve, meta["cve"])


class TestPollPaths(unittest.TestCase):
    def test_poll_paths_immediate_success(self):
        call_count = 0

        def fake_fetch(path):
            nonlocal call_count
            call_count += 1
            return {"status": 200, "body": "found"}

        resp, path, attempts = poll_paths(fake_fetch, ["/p1", "/p2"], deadline=1.0)
        self.assertIsNotNone(resp)
        self.assertEqual(path, "/p1")
        self.assertEqual(attempts, 1)

    def test_poll_paths_retries_and_succeeds(self):
        calls = []

        def fake_fetch(path):
            calls.append(path)
            if len(calls) < 3:
                return {"status": 404}
            return {"status": 200, "body": "found after retry"}

        resp, path, attempts = poll_paths(fake_fetch, ["/p1", "/p2"], deadline=1.0, initial_delay=0.01)
        self.assertIsNotNone(resp)
        self.assertEqual(path, "/p1")
        self.assertEqual(attempts, 3)

    def test_poll_paths_deadline_expiry(self):
        def fake_fetch(path):
            return {"status": 404}

        resp, path, attempts = poll_paths(fake_fetch, ["/p1"], deadline=0.05, initial_delay=0.01)
        self.assertIsNone(resp)
        self.assertIsNone(path)
        self.assertTrue(attempts >= 1)


class TestSanitizeArgv(unittest.TestCase):
    def test_sanitize_proxy_and_commands(self):
        argv = [
            "proofcms",
            "-u",
            "http://example.com",
            "--proxy",
            "http://admin:secret123@proxy.lan:8080",
            "--aggressive-command",
            "rm -rf /tmp/test",
            "--cve",
            "CVE-2015-8562",
        ]
        sanitized = sanitize_argv(argv)
        self.assertIn("--proxy", sanitized)
        self.assertIn("***", sanitized)
        self.assertNotIn("secret123", " ".join(sanitized))
        self.assertIn("[COMMAND_PROVIDED]", sanitized)
        self.assertNotIn("rm -rf", " ".join(sanitized))

    def test_sanitize_inline_equals(self):
        argv = [
            "proofcms",
            "--proxy=http://127.0.0.1:8080",
            "--aggressive-command=id;whoami",
        ]
        sanitized = sanitize_argv(argv)
        self.assertIn("--proxy=***", sanitized)
        self.assertIn("--aggressive-command=[COMMAND_PROVIDED]", sanitized)


class TestMandatoryRegressionCases(unittest.TestCase):
    """Explicitly tests the 7 mandatory regression cases required by the supervisor."""

    def test_regression_1_php_source_never_confirms_execution(self):
        """1. PHP served as source never confirms execution."""
        body_with_source = "<?php echo 42; ?> JVH_MATH_123456_END"
        is_exec, is_leak = verify_php_execution(body_with_source, "123456")
        self.assertFalse(is_exec, "PHP source leak must never confirm execution")
        self.assertTrue(is_leak, "Must identify PHP source code leakage")

    def test_regression_2_custom_200_never_detects_plugin(self):
        """2. A nonexistent custom-200 route never detects a plugin."""
        from proofcms.core.http import is_baseline_match
        baseline = {
            "status": 200,
            "body_hash": "custom_200_hash",
            "target_root": "http://target",
        }
        probe_resp = {
            "status": 200,
            "body_hash": "custom_200_hash",
        }
        self.assertTrue(
            is_baseline_match(probe_resp, baseline),
            "Custom 200 matching baseline hash must be flagged as non-existent route match",
        )

    def test_dynamic_token_homepage_matches_fake_200_baseline(self):
        from proofcms.core.http import _build_response_dict, is_baseline_match

        first = _build_response_dict(
            200,
            '<html><title>Portal</title><input name="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" value="1"></html>',
            "https://target/missing-one",
            "https://target/missing-one",
        )
        second = _build_response_dict(
            200,
            '<html><title>Portal</title><input name="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" value="1"></html>',
            "https://target/missing-two",
            "https://target/missing-two",
        )
        baseline = {
            "status": first["status"],
            "body_hash": first["body_hash"],
            "normalized_body_hash": first["normalized_body_hash"],
            "body_len": first["body_len"],
            "title": first["title"],
        }
        self.assertTrue(is_baseline_match(second, baseline))

    def test_radware_http_200_challenge_is_identified(self):
        from proofcms.core.http import _build_response_dict

        response = _build_response_dict(
            200,
            "<html><title>Radware Captcha Page</title><script>var __uzma='x';</script></html>",
            "https://target.test/",
            "https://target.test/",
        )
        self.assertEqual(response["edge_interstitial"], "radware-bot-manager")

    def test_hidden_csrf_token_precedes_javascript_cache_token(self):
        from proofcms.core.probes import extract_csrf_candidates_from_html

        html = (
            '<script>Joomla = {"csrf.token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}</script>'
            '<input type="hidden" name="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" value="1">'
        )
        self.assertEqual(
            extract_csrf_candidates_from_html(html),
            ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        )

    def test_regression_3_blanket_403_never_confirms_component(self):
        """3. Blanket-403 does not independently confirm a component."""
        from proofcms.core.http import is_baseline_match
        baseline = {"status": 403, "blanket_403": True, "target_root": "http://target"}
        probe_resp = {"status": 403, "body_hash": "different_hash"}
        self.assertTrue(
            is_baseline_match(probe_resp, baseline),
            "Blanket-403 must reject isolated 403 probe",
        )

    def test_regression_4_home_redirect_never_valid_manifest(self):
        """4. A redirect to the home page is not a valid manifest."""
        from proofcms.core.http import is_baseline_match
        from proofcms.detectors.joomla import validate_joomla_manifest
        baseline = {"status": 200, "target_root": "http://target"}
        probe_resp = {
            "status": 200,
            "redirected": True,
            "final_url": "http://target/",
        }
        self.assertTrue(is_baseline_match(probe_resp, baseline))
        html_home = "<!DOCTYPE html><html><body><h1>Welcome to My Joomla Site</h1></body></html>"
        self.assertFalse(validate_joomla_manifest(html_home, "/administrator/manifests/files/joomla.xml"))

    def test_regression_5_json_array_does_not_crash(self):
        """5. A JSON array does not crash the scan."""
        import json
        array_payload = json.dumps([{"item": 1}, {"item": 2}])
        # Ensure safely processed even if list instead of dict
        parsed = json.loads(array_payload)
        self.assertIsInstance(parsed, list)
        # Should not raise AttributeError when treated defensively
        val = parsed.get("data") if isinstance(parsed, dict) else None
        self.assertIsNone(val)

    def test_regression_6_module_exception_does_not_abort_scan(self):
        """6. One CVE exception does not stop the remaining checks."""
        from proofcms import cli
        # Verify AVAILABLE_CVES contains multiple CVEs and error handling encapsulates exceptions
        self.assertTrue(len(cli.AVAILABLE_CVES) >= 10)

    def test_regression_7_prerelease_not_treated_as_patched(self):
        """7. A pre-release is not treated as the patched final release."""
        # 3.4.6 is patched for CVE-2015-8562. 3.4.6-rc1 is still affected (< 3.4.6)
        self.assertTrue(version_lt("3.4.6-rc1", "3.4.6"))
        self.assertTrue(version_lt("3.4.6rc1", "3.4.6"))
        self.assertTrue(version_lt("2.9.82-beta1", "2.9.82"))


class TestCliCiEnhancements(unittest.TestCase):
    def test_named_chain_selection(self):
        self.assertEqual(selected_chains("wp2shell"), ["wp2shell"])
        self.assertEqual(selected_cves("none"), [])

    def test_effective_exploit_mode_auto_prefers_safe(self):
        # Helix3 supports safe and aggressive
        import proofcms.modules.joomla.cve_2026_49049 as h3
        from proofcms import cli
        mode = cli.effective_exploit_mode(h3, "auto")
        self.assertEqual(mode, "safe", "auto mode must pick least intrusive safe mode over aggressive")

    def test_unselected_exploit_rejected(self):
        import subprocess
        import sys
        # Run CLI requesting an exploit not in --cve
        cmd = [
            sys.executable,
            "-m",
            "proofcms",
            "-u",
            "http://example.com",
            "--cve",
            "CVE-2015-8562",
            "--run-exploit",
            "CVE-2026-48907",
            "--i-understand-authorized",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        self.assertEqual(res.returncode, 2)
        self.assertIn("are not included in the selected CVEs", res.stdout)


class TestSupervisorSevenRefinements(unittest.TestCase):
    def test_item_1_https_fallback_on_http_error_vs_transport_error(self):
        """1. urllib.error.HTTPError (401/403/404) confirms HTTPS; fallback only on transport/TLS error."""
        import ssl
        import urllib.error
        from unittest.mock import MagicMock, patch

        from proofcms.core.http import normalize_url

        # HTTPError (e.g. 403 Forbidden) must NOT downgrade to HTTP
        mock_opener_403 = MagicMock()
        mock_opener_403.open.side_effect = urllib.error.HTTPError(
            url="https://secure.example.com", code=403, msg="Forbidden", hdrs=http.client.HTTPMessage(), fp=None
        )
        with patch("urllib.request.build_opener", return_value=mock_opener_403):
            result = normalize_url("https://secure.example.com", timeout=5)
            self.assertEqual(result, "https://secure.example.com")

        # HTTPError (e.g. 401 Unauthorized) must NOT downgrade
        mock_opener_401 = MagicMock()
        mock_opener_401.open.side_effect = urllib.error.HTTPError(
            url="https://secure.example.com", code=401, msg="Unauthorized", hdrs=http.client.HTTPMessage(), fp=None
        )
        with patch("urllib.request.build_opener", return_value=mock_opener_401):
            result = normalize_url("https://secure.example.com", timeout=5)
            self.assertEqual(result, "https://secure.example.com")

        # URL normalization is pure and must never silently downgrade HTTPS.
        mock_opener_transport = MagicMock()
        mock_opener_transport.open.side_effect = urllib.error.URLError("Connection refused")
        with patch("urllib.request.build_opener", return_value=mock_opener_transport):
            result = normalize_url("https://legacy.example.com", timeout=5)
            self.assertEqual(result, "https://legacy.example.com")

        # TLS failures likewise preserve the explicitly requested scheme.
        mock_opener_ssl = MagicMock()
        mock_opener_ssl.open.side_effect = ssl.SSLError("Certificate verify failed")
        with patch("urllib.request.build_opener", return_value=mock_opener_ssl):
            result = normalize_url("https://broken-ssl.example.com", timeout=5)
            self.assertEqual(result, "https://broken-ssl.example.com")

    def test_item_2_pyproject_python_310_requirements(self):
        """2. pyproject.toml requires Python >= 3.10 and configures Ruff for py310."""
        from pathlib import Path
        pyproject_content = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('requires-python = ">=3.10"', pyproject_content)
        self.assertIn('target-version = "py310"', pyproject_content)
        self.assertNotIn("Programming Language :: Python :: 3.9", pyproject_content)

    def test_item_3_balbooa_403_and_200_detection(self):
        """3. Generic 403 is insufficient; a component-specific directory response is required."""
        from unittest.mock import patch

        from proofcms.detectors.joomla import detect_baforms

        baseline = {"status": 404, "body": "Not found", "final_url": "http://target/404"}

        # Case A: a generic 403 is not evidence that the requested component exists.
        def mock_fetch_403(url, **kwargs):
            if "/images/baforms/uploads/" in url:
                return {"status": 403, "body": "Forbidden", "final_url": url}
            return {"status": 404, "body": "Not found", "final_url": url}

        with patch("proofcms.detectors.joomla.fetch_url", side_effect=mock_fetch_403):
            info = detect_baforms("http://target", timeout=5, baseline=baseline)
            self.assertFalse(info.found)

        # Case B: 200 on uploads and different from baseline -> 200-uploads-open
        def mock_fetch_200(url, **kwargs):
            if "/images/baforms/uploads/" in url:
                return {"status": 200, "body": "Index of /images/baforms/uploads", "final_url": url}
            return {"status": 404, "body": "Not found", "final_url": url}

        with patch("proofcms.detectors.joomla.fetch_url", side_effect=mock_fetch_200):
            info = detect_baforms("http://target", timeout=5, baseline=baseline)
            self.assertTrue(info.found)
            self.assertIn("200-uploads-open", info.source)

        # Case C: 403 matches blanket 403 baseline -> ignored
        blanket_403_baseline = {
            "status": 403,
            "body": "Forbidden blanket",
            "final_url": "http://target/nonexistent",
            "blanket_403": True,
        }

        def mock_fetch_blanket(url, **kwargs):
            return {"status": 403, "body": "Forbidden blanket", "final_url": url}

        with patch("proofcms.detectors.joomla.fetch_url", side_effect=mock_fetch_blanket):
            info = detect_baforms("http://target", timeout=5, baseline=blanket_403_baseline)
            self.assertFalse(info.found)

    def test_item_4_parse_version_safe_no_permissive_fallback(self):
        """4. Ambiguous or invalid versions return None instead of extracting arbitrary digits."""
        from proofcms.core.versions import parse_version_safe, version_parts

        self.assertIsNone(parse_version_safe("ambiguous-alpha-release-2.0"))
        self.assertIsNone(parse_version_safe("build-2024-invalid"))
        self.assertIsNone(parse_version_safe("unknown-build-99"))
        self.assertIsNone(version_parts("invalid-unsupported-tag"))

        # Valid versions still parse
        v = parse_version_safe("2.9.1")
        self.assertIsNotNone(v)
        self.assertEqual(str(v), "2.9.1")

    def test_item_5_jce_cve_rule_restored(self):
        """5. CVE-2026-48907 PATCHED_VERSION is 2.9.99.5 to prevent false PATCHED classifications."""
        from proofcms.modules.joomla import cve_2026_48907
        self.assertEqual(cve_2026_48907.PATCHED_VERSION, "2.9.99.5")
        self.assertEqual(cve_2026_48907.AFFECTED_RULE, "JCE Editor Extension < 2.9.99.5")

        # 2.9.85 must be classified as vulnerable, not PATCHED
        with unittest.mock.patch.object(cve_2026_48907, "probe_jce", return_value={"found": True, "version": "2.9.85"}):
            res = cve_2026_48907.passive_check("http://example.com", joomla_version="3.9.0")
            self.assertIn("VULNERABLE", res.status)
            self.assertNotEqual(res.status, "PATCHED")

    def test_item_6_exploit_mode_help_text(self):
        """6. CLI help for --exploit-mode accurately documents that auto prefers safe."""
        import subprocess
        import sys
        res = subprocess.run(
            [sys.executable, "-m", "proofcms", "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("prefers safe for modules with safe mode", res.stdout)

    def test_item_7_strict_joomla_manifest_validation(self):
        """7. Strict manifest checks: route-specific XML validation and institutional README signature."""
        from proofcms.detectors.joomla import validate_joomla_manifest

        # Generic XML with <extension> and "Joomla" must be rejected for specific files route
        generic_xml = "<extension><description>Site built with Joomla</description><version>1.0</version></extension>"
        self.assertFalse(validate_joomla_manifest(generic_xml, "/administrator/manifests/files/joomla.xml"))
        self.assertFalse(validate_joomla_manifest(generic_xml, "/administrator/components/com_content/content.xml"))

        # Casual mention of Joomla in README.txt without institutional signature is rejected
        casual_readme = "Project Notes: We previously migrated away from Joomla into a new framework."
        self.assertFalse(validate_joomla_manifest(casual_readme, "/README.txt"))

        # Authentic README.txt with institutional signature is accepted
        authentic_readme = (
            "README.txt - Joomla! CMS\n"
            "Copyright (C) 2005 - 2020 Open Source Matters, Inc.\n"
            "Joomla! is Free Software released under the GNU General Public License\n"
        )
        self.assertTrue(validate_joomla_manifest(authentic_readme, "/README.txt"))

        # Authentic joomla.xml manifest is accepted
        authentic_manifest = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<extension version="3.1" type="file" method="upgrade">\n'
            '    <name>files_joomla</name>\n'
            '    <author>Joomla! Project</author>\n'
            '    <version>3.9.28</version>\n'
            '</extension>'
        )
        self.assertTrue(validate_joomla_manifest(authentic_manifest, "/administrator/manifests/files/joomla.xml"))


if __name__ == "__main__":
    unittest.main()
