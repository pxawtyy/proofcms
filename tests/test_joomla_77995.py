from __future__ import annotations

from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_77995

MANIFEST = '<extension><version>3.1.4</version></extension>'
PATCHED_MANIFEST = '<extension><version>3.2.2</version></extension>'


class _FakeClient:
    def __init__(self, manifest: str = MANIFEST, body: str = "", authenticated: bool = False) -> None:
        self.manifest = manifest
        self.body = body
        self.authenticated = authenticated
        self.headers: list[dict[str, str] | None] = []

    def get(self, url: str, headers=None, timeout: int | None = None) -> dict[str, object]:
        self.headers.append(headers)
        if url.endswith(cve_2026_77995.MANIFEST_PATH):
            return {"status": 200, "body": self.manifest}
        if self.authenticated:
            return {"status": 200, "body": "Control Panel com_cpanel task=logout"}
        return {"status": 200, "body": self.body or '<form class="form-login" id="mod-login-username">'}

    def request(
        self,
        url: str,
        method: str = "GET",
        headers=None,
        data=None,
        timeout: int | None = None,
        follow_redirects: bool = True,
    ) -> dict[str, object]:
        self.headers.append(headers)
        return {
            "status": 303,
            "body": "",
            "headers_multi": {"set-cookie": ["a" * 32 + "=" + "b" * 32 + "; path=/; HttpOnly"]},
        }


def test_77995_version_boundaries():
    assert cve_2026_77995.classify_version("3.1.4") == "LIKELY_VULNERABLE"
    assert cve_2026_77995.classify_version("3.1.9") == "LIKELY_VULNERABLE"
    assert cve_2026_77995.classify_version("3.2.0") == "NOT_AFFECTED"
    assert cve_2026_77995.classify_version("3.2.2") == "NOT_AFFECTED"
    assert cve_2026_77995.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_77995_manifest_version_extraction():
    assert cve_2026_77995._version_from_manifest(MANIFEST) == "3.1.4"
    assert cve_2026_77995._version_from_manifest("<html>no version</html>") is None


def test_77995_session_cookie_ignores_deleted_bridge_cookies():
    class _Response(dict):
        pass

    response = _Response(
        headers_multi={
            "set-cookie": [
                "mo_site=deleted; expires=Thu, 01 Jan 1970 00:00:00 GMT",
                "a" * 32 + "=" + "b" * 32 + "; path=/; HttpOnly",
            ]
        }
    )
    assert cve_2026_77995._session_cookie(response) == "a" * 32 + "=" + "b" * 32


def test_77995_safe_probe_reads_manifest():
    client = _FakeClient()
    with patch.object(cve_2026_77995, "HttpClient", return_value=client):
        result = cve_2026_77995.run_safe_probe("https://target.test")
    assert result.status == "LIKELY_VULNERABLE"
    assert result.component_version == "3.1.4"
    assert result.exploit_ran is False


def test_77995_bridge_confirms_admin_takeover():
    client = _FakeClient(authenticated=True)
    with patch.object(cve_2026_77995, "HttpClient", return_value=client):
        result = cve_2026_77995.run_aggressive_probe("https://target.test")
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["authenticated"] is True
    assert result.evidence["session_cookie_replayed"] is True


def test_77995_login_form_is_not_confirmed():
    client = _FakeClient()
    with patch.object(cve_2026_77995, "HttpClient", return_value=client):
        result = cve_2026_77995.run_aggressive_probe("https://target.test")
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["login_form"] is True


def test_77995_patched_version_skips_aggressive():
    client = _FakeClient(manifest=PATCHED_MANIFEST, authenticated=True)
    with patch.object(cve_2026_77995, "HttpClient", return_value=client):
        result = cve_2026_77995.run_aggressive_probe("https://target.test")
    assert result.status == "NOT_AFFECTED"


def test_77995_check_sends_no_payload_in_safe_mode():
    client = _FakeClient()
    with patch.object(cve_2026_77995, "HttpClient", return_value=client):
        result = cve_2026_77995.check("https://target.test", run_exploit_check=True, exploit_mode="safe")
    assert result.status == "LIKELY_VULNERABLE"
    assert result.exploit_ran is False
