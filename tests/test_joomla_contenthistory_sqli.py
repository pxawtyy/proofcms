"""Unit tests for the Joomla 20151001 content-history SQL injection modules."""
import unittest
from unittest.mock import patch

from proofcms.modules.joomla import contenthistory_sqli, cve_2015_7297, cve_2015_7858

CONTROL = "<html>Error: 500 Layout default not found</html>"
XPATH_ERROR = (
    "<html>Error: 500 XPATH syntax error: &#039;~10.11.19-MariaDB-ubu2204&#039; "
    "SQL=SELECT 1,extractvalue(1,concat(0x7e,(select version())))...</html>"
)
TABLE_ERROR = (
    "<html>Error: 500 Table &#039;joomla.proofcms_missing_table&#039; doesn&#039;t exist "
    "SQL=SELECT 1,(SELECT 1 FROM proofcms_missing_table)...</html>"
)


class FakeClient:
    def __init__(self, state):
        self.state = state

    def _response(self, body, status=500):
        return {
            "status": status,
            "body": body,
            "body_hash": str(hash(body)),
            "headers": {},
            "redirected": False,
        }

    def get(self, url, **kwargs):
        if "extractvalue" in url:
            body = XPATH_ERROR if self.state.get("vulnerable") else CONTROL
            return self._response(body)
        return self._response(CONTROL)

    def request(self, url, **kwargs):
        data = kwargs.get("data") or b""
        probe = b"proofcms_missing_table" in data
        if probe:
            body = TABLE_ERROR if self.state.get("vulnerable") else CONTROL
        else:
            body = CONTROL
        return self._response(body)


def _run(module, state):
    with patch.object(contenthistory_sqli, "HttpClient", side_effect=lambda *a, **k: FakeClient(state)):
        return module.check(
            "https://target.test",
            joomla_version="3.4.4",
            run_exploit_check=True,
            exploit_mode="safe",
            timeout=2,
        )


class TestContentHistorySqli(unittest.TestCase):
    def test_7297_error_based_payload_confirms(self):
        result = _run(cve_2015_7297, {"vulnerable": True})
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertTrue(result.evidence["probe_sql_error"])
        self.assertEqual(result.evidence["database_version"], "10.11.19-MariaDB-ubu2204")

    def test_7297_control_without_error_does_not_confirm(self):
        result = _run(cve_2015_7297, {"vulnerable": False})
        self.assertEqual(result.status, "NOT_CONFIRMED")

    def test_7858_missing_table_payload_confirms(self):
        result = _run(cve_2015_7858, {"vulnerable": True})
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.confidence, "CONFIRMED")
        self.assertEqual(result.evidence["method"], "POST")
        self.assertTrue(result.evidence["signature_hit"])

    def test_7858_control_without_error_does_not_confirm(self):
        result = _run(cve_2015_7858, {"vulnerable": False})
        self.assertEqual(result.status, "NOT_CONFIRMED")

    def test_version_gates(self):
        for module in (cve_2015_7297, cve_2015_7858):
            self.assertEqual(module.classify_version("3.2.0"), "LIKELY_VULNERABLE")
            self.assertEqual(module.classify_version("3.4.4"), "LIKELY_VULNERABLE")
            self.assertEqual(module.classify_version("3.4.5"), "PATCHED")
            self.assertEqual(module.classify_version("3.1.5"), "NOT_AFFECTED")
            self.assertEqual(module.classify_version(None), "INCONCLUSIVE")

    def test_unsafe_mode_is_not_run(self):
        result = cve_2015_7297.check(
            "https://target.test",
            joomla_version="3.4.4",
            run_exploit_check=True,
            exploit_mode="aggressive",
        )
        self.assertEqual(result.status, "LIKELY_VULNERABLE")


if __name__ == "__main__":
    unittest.main()
