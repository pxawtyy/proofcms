from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_57829, cve_2026_102426


def _plugin(name: str, version: str) -> dict[str, dict[str, object]]:
    return {name: {"found": True, "version": version}}


def test_helix_57829_version_boundaries_and_inventory():
    assert cve_2026_57829.classify_version("2.2.6") == "LIKELY_VULNERABLE"
    assert cve_2026_57829.classify_version("2.2.7") == "NOT_AFFECTED"
    assert cve_2026_57829.classify_version(None) == "DETECTED_VERSION_UNKNOWN"
    assert cve_2026_57829.check("https://target.test", plugins=_plugin("helixultimate", "2.2.10.0.1")).status == "NOT_AFFECTED"


def test_helix_57829_safe_probe_does_not_write_state():
    with patch.object(cve_2026_57829, "request", return_value={"status": 200, "redirected": False, "body": "{}"}) as req:
        result = cve_2026_57829.check("https://target.test", run_exploit_check=True, plugins=_plugin("helixultimate", "2.2.6"))
    assert result.status == "BLOCKED_EXTERNAL"
    assert req.call_args.kwargs.get("timeout") == 12


class _HelixLabClient:
    """Minimal HttpClient stand-in for the mega-menu write/restore flow."""

    def __init__(self, first_page: str, write_body: str, restore_body: str | None = None, write_status: int = 200):
        self.first_page = first_page
        self.write_body = write_body
        self.restore_body = restore_body or write_body
        self.write_status = write_status
        self.marker = ""
        self.gets = 0
        self.writes: list[str] = []

    def get(self, url: str, timeout: int | None = None) -> dict[str, object]:
        self.gets += 1
        if self.gets == 1:
            return {"status": 200, "body": self.first_page}
        if self.gets == 2:
            return {"status": 200, "body": f'<li class="item-101 {self.marker}">Home</li>'}
        return {"status": 200, "body": '<li class="item-101">Home</li>'}

    def request(self, url: str, method: str = "GET", headers=None, data=None, timeout=None, follow_redirects=True):
        body = data.decode() if isinstance(data, bytes) else str(data or "")
        self.writes.append(body)
        if "settings%5Bcustomclass%5D" in body:
            marker = body.split("settings%5Bcustomclass%5D=")[1].split("&")[0]
            from urllib.parse import unquote

            self.marker = unquote(marker)
            return {"status": self.write_status, "body": self.write_body}
        return {"status": 200, "body": self.restore_body}


def test_helix_57829_aggressive_marker_write_is_confirmed_and_cleaned_up():
    write_body = '{"success":true,"data":{"status":true,"data":true}}'
    client = _HelixLabClient('<li class="item-101 default">Home</li>', write_body)
    with patch.object(cve_2026_57829, "HttpClient", return_value=client):
        result = cve_2026_57829.check(
            "https://target.test",
            run_exploit_check=True,
            exploit_mode="aggressive",
            plugins=_plugin("helixultimate", "2.2.6"),
        )
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.cleanup_attempted is True
    assert result.cleanup_verified is True
    assert result.evidence["menu_item"] == 101
    assert result.evidence["marker_rendered"] is True
    assert len(client.writes) == 2


def test_helix_57829_aggressive_refused_write_matches_patched_control():
    refused = '{"success":true,"data":{"status":false,"message":"You are not authorised to view this resource."}}'
    client = _HelixLabClient('<li class="item-101 default">Home</li>', refused)
    with patch.object(cve_2026_57829, "HttpClient", return_value=client):
        result = cve_2026_57829.check(
            "https://target.test",
            run_exploit_check=True,
            exploit_mode="aggressive",
            plugins=_plugin("helixultimate", "2.2.6"),
        )
    assert result.status == "NOT_CONFIRMED"
    assert "refused the write" in result.detail
    assert result.evidence["write_accepted"] is False


def test_helix_57829_aggressive_redirect_guard_is_not_confirmed():
    client = _HelixLabClient('<li class="item-101 default">Home</li>', "", write_status=303)
    with patch.object(cve_2026_57829, "HttpClient", return_value=client):
        result = cve_2026_57829.check(
            "https://target.test",
            run_exploit_check=True,
            exploit_mode="aggressive",
            plugins=_plugin("helixultimate", "2.2.6"),
        )
    assert result.status == "NOT_CONFIRMED"
    assert "redirect" in result.detail
    assert result.evidence["write_accepted"] is False


def test_helix_57829_aggressive_without_menu_item_is_blocked():
    client = _HelixLabClient("<html>no menu markup</html>", "{}")
    with patch.object(cve_2026_57829, "HttpClient", return_value=client):
        result = cve_2026_57829.run_aggressive_probe("https://target.test")
    assert result.status == "BLOCKED_EXTERNAL"
    assert client.writes == []


def test_sp_page_builder_102426_version_boundaries_and_inventory():
    assert cve_2026_102426.classify_version("3.0.0") == "LIKELY_VULNERABLE"
    assert cve_2026_102426.classify_version("5.6.1p2") == "LIKELY_VULNERABLE"
    assert cve_2026_102426.classify_version("5.6.2") == "NOT_AFFECTED"
    assert cve_2026_102426.check("https://target.test", plugins=_plugin("sppagebuilder", "6.10.0")).status == "NOT_AFFECTED"


def test_sp_page_builder_102426_safe_marker_probe_classifies_reflection():
    import re

    def reflected(url: str, **kwargs: object) -> dict[str, object]:
        marker = re.search(r"PROOFCMS_DCF_[A-Fa-f0-9]+", url).group(0)
        return {"status": 200, "body": f"l-r<{marker}>"}

    with patch.object(cve_2026_102426, "request", side_effect=reflected):
        result = cve_2026_102426.check("https://target.test", run_exploit_check=True, plugins=_plugin("sppagebuilder", "5.6.1"))
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"


def test_sp_page_builder_102426_escaped_marker_is_not_confirmed():
    with patch.object(cve_2026_102426, "request", return_value={"status": 200, "body": "&lt;PROOFCMS_DCF_fake&gt;"}):
        result = cve_2026_102426.run_safe_probe("https://target.test")
    assert result.status == "NOT_CONFIRMED"
