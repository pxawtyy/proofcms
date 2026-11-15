from __future__ import annotations

import re
from unittest.mock import patch
from urllib.parse import unquote

from proofcms.modules.joomla import cve_2026_67364, cve_2026_67365, cve_2026_74254, cve_2026_77994


class _DummyClient:
    def __init__(self, *args, **kwargs) -> None:
        pass

    def get(self, url: str, timeout: int | None = None) -> dict[str, object]:
        return {"status": 200, "body": ""}

    def post(self, url: str, fields=None, timeout=None) -> dict[str, object]:
        return {"status": 200, "body": ""}

    def request(self, url: str, method: str = "POST", headers=None, data=None, timeout=None, follow_redirects=False):
        return {"status": 200, "body": ""}


# --- CVE-2026-77994 -------------------------------------------------------


def test_pagebuilderck_77994_version_boundaries():
    assert cve_2026_77994.classify_version("3.5.4") == "LIKELY_VULNERABLE"
    assert cve_2026_77994.classify_version("3.6.4") == "LIKELY_VULNERABLE"
    assert cve_2026_77994.classify_version("3.6.5") == "NOT_AFFECTED"
    assert cve_2026_77994.classify_version("3.6.7") == "NOT_AFFECTED"
    assert cve_2026_77994.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_pagebuilderck_77994_sleep_confirms():
    responses = [({"status": 200, "body": ""}, 0.20), ({"status": 200, "body": ""}, 2.20)]
    with patch.object(cve_2026_77994, "HttpClient", return_value=_DummyClient()), patch.object(
        cve_2026_77994, "_timed_get", side_effect=responses
    ):
        result = cve_2026_77994.run_aggressive_probe("https://target.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["delta_seconds"] >= cve_2026_77994.SLEEP_THRESHOLD


def test_pagebuilderck_77994_patched_is_not_confirmed():
    responses = [({"status": 200, "body": ""}, 0.20), ({"status": 200, "body": ""}, 0.30)]
    with patch.object(cve_2026_77994, "HttpClient", return_value=_DummyClient()), patch.object(
        cve_2026_77994, "_timed_get", side_effect=responses
    ):
        result = cve_2026_77994.run_aggressive_probe("https://target.test")
    assert result.status == "NOT_CONFIRMED"


# --- CVE-2026-74254 -------------------------------------------------------


def test_pagebuilderck_74254_version_boundaries():
    assert cve_2026_74254.classify_version("3.5.4") == "LIKELY_VULNERABLE"
    assert cve_2026_74254.classify_version("3.6.5") == "NOT_AFFECTED"
    assert cve_2026_74254.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_pagebuilderck_74254_backend_sleep_confirms():
    responses = [({"status": 200, "body": ""}, 0.10), ({"status": 200, "body": ""}, 2.10)]
    with patch.object(cve_2026_74254, "HttpClient", return_value=_DummyClient()), patch.object(
        cve_2026_74254, "joomla_admin_login", return_value=True
    ), patch.object(cve_2026_74254, "extract_csrf_from_html", return_value="a" * 32), patch.object(
        cve_2026_74254, "_timed_get", side_effect=responses
    ):
        result = cve_2026_74254.run_aggressive_probe(
            "https://target.test", username="admin", password="secret"
        )
    assert result.status == "VULNERABLE"
    assert result.evidence["login_ok"] is True


def test_pagebuilderck_74254_missing_credentials_is_blocked():
    result = cve_2026_74254.run_aggressive_probe("https://target.test")
    assert result.status == "BLOCKED_EXTERNAL"


# --- CVE-2026-67364 -------------------------------------------------------


class _FakeBaFormsUrlClient:
    def __init__(self, execute: bool = True) -> None:
        self.execute = execute
        self.marker = ""

    def get(self, url: str, timeout: int | None = None) -> dict[str, object]:
        return {"status": 200, "body": '<script>{"csrf.token":"' + "a" * 32 + '"}</script>'}

    def request(self, url: str, method: str = "POST", headers=None, data=None, timeout=None, follow_redirects=False):
        decoded = unquote(url)
        match = re.search(r"PROOFCMS_BAFORMS_URL_RCE_[a-f0-9]+", decoded)
        self.marker = match.group(0) if match else ""
        if self.execute:
            return {"status": 200, "body": self.marker + '{"status":true}'}
        return {"status": 200, "body": '{"status":true}'}


def test_baforms_67364_version_boundaries():
    assert cve_2026_67364.classify_version("2.4.3.1") == "LIKELY_VULNERABLE"
    assert cve_2026_67364.classify_version("2.4.3.2") == "NOT_AFFECTED"
    assert cve_2026_67364.classify_version("2.4.4.0") == "NOT_AFFECTED"
    assert cve_2026_67364.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_baforms_67364_url_parameter_confirms():
    with patch.object(cve_2026_67364, "HttpClient", return_value=_FakeBaFormsUrlClient(True)):
        result = cve_2026_67364.run_aggressive_probe("https://target.test")
    assert result.status == "VULNERABLE"
    assert result.evidence["marker_executed"] is True


def test_baforms_67364_patched_is_not_confirmed():
    with patch.object(cve_2026_67364, "HttpClient", return_value=_FakeBaFormsUrlClient(False)):
        result = cve_2026_67364.run_aggressive_probe("https://target.test")
    assert result.status == "NOT_CONFIRMED"


# --- CVE-2026-67365 -------------------------------------------------------


def test_icagenda_67365_version_boundaries():
    assert cve_2026_67365.classify_version("4.0.7") == "LIKELY_VULNERABLE"
    assert cve_2026_67365.classify_version("4.0.11") == "LIKELY_VULNERABLE"
    assert cve_2026_67365.classify_version("4.0.12") == "NOT_AFFECTED"
    assert cve_2026_67365.classify_version("3.9.14") == "NOT_AFFECTED"
    assert cve_2026_67365.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_icagenda_67365_sleep_confirms():
    responses = [({"status": 200, "body": ""}, 0.30), ({"status": 200, "body": ""}, 4.20)]
    with patch.object(cve_2026_67365, "HttpClient", return_value=_DummyClient()), patch.object(
        cve_2026_67365, "_timed_get", side_effect=responses
    ):
        result = cve_2026_67365.run_aggressive_probe("https://target.test", year=2026, month=11)
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"


def test_icagenda_67365_patched_is_not_confirmed():
    responses = [({"status": 200, "body": ""}, 0.30), ({"status": 200, "body": ""}, 0.40)]
    with patch.object(cve_2026_67365, "HttpClient", return_value=_DummyClient()), patch.object(
        cve_2026_67365, "_timed_get", side_effect=responses
    ):
        result = cve_2026_67365.run_aggressive_probe("https://target.test", year=2026, month=11)
    assert result.status == "NOT_CONFIRMED"
