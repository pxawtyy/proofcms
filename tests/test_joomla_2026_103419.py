from __future__ import annotations

import json
from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_103419

TOKEN = "a" * 32
MEDIA = "proofcms103419<img src=x onerror=alert(1)>.png"


class _FakeHelixClient:
    def __init__(self, escaped: bool = False) -> None:
        self.escaped = escaped

    def get(self, url: str, timeout=None):
        return {"status": 200, "body": f'name="{TOKEN}" value="1"'}

    def request(self, url: str, method: str = "GET", headers=None, data=None, timeout=None):
        name = MEDIA.replace("<", "&lt;").replace(">", "&gt;") if self.escaped else MEDIA
        output = f'<li data-path="images/{name}"><img src="images/{name}"></li>'
        return {"status": 200, "body": json.dumps({"status": True, "output": output})}


def test_helix_103419_version_boundaries():
    assert cve_2026_103419.classify_version("2.2.10") == "LIKELY_VULNERABLE"
    assert cve_2026_103419.classify_version("2.2.11") == "NOT_AFFECTED"
    assert cve_2026_103419.classify_version(None) == "DETECTED_VERSION_UNKNOWN"


def test_helix_103419_raw_media_name_confirms():
    with patch.object(cve_2026_103419, "HttpClient", return_value=_FakeHelixClient()), patch.object(
        cve_2026_103419, "_frontend_login", return_value=True
    ):
        result = cve_2026_103419.run_aggressive_probe(
            "https://target.test", username="admin", password="secret"
        )
    assert result.status == "VULNERABLE"
    assert result.evidence["raw_tag"] is True


def test_helix_103419_escaped_media_name_is_not_confirmed():
    with patch.object(cve_2026_103419, "HttpClient", return_value=_FakeHelixClient(escaped=True)), patch.object(
        cve_2026_103419, "_frontend_login", return_value=True
    ):
        result = cve_2026_103419.run_aggressive_probe(
            "https://target.test", username="admin", password="secret"
        )
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["escaped_tag"] is True


def test_helix_103419_passive_reports_vulnerable_version():
    result = cve_2026_103419.passive_result({"helixultimate": {"found": True, "version": "2.2.10"}})
    assert result.status == "LIKELY_VULNERABLE"
