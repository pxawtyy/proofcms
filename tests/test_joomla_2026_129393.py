from __future__ import annotations

import re
import urllib.parse
from unittest.mock import patch

from proofcms.modules.joomla import cve_2026_129393 as media_rce

TOKEN = "0123456789abcdef0123456789abcdef"


def _marker_from_data(data: bytes | str | None) -> str:
    text = data.decode() if isinstance(data, bytes) else str(data or "")
    parsed = urllib.parse.parse_qs(text)
    payload = parsed.get("jform[fieldparams][directory]", [""])[0]
    match = re.search(r"proofcms-xml-[0-9a-f]+", payload)
    return match.group(0) if match else "proofcms-xml-missing"


class FakeClient:
    def __init__(self, article_has_class: bool = True) -> None:
        self.article_has_class = article_has_class
        self.marker = ""
        self.calls: list[str] = []

    def get(self, url: str, timeout: int | None = None) -> dict:
        self.calls.append(f"GET {url}")
        if "option=com_fields&view=field&layout=edit" in url:
            return {"status": 200, "body": f'<input type="hidden" name="{TOKEN}" value="1">'}
        if "option=com_content&task=article.add" in url:
            if self.article_has_class:
                body = f'<input class="form-control {self.marker}" value="">'
            else:
                body = f'<input value="images&quot; class=&quot;{self.marker}&quot; x=&quot;">'
            return {"status": 200, "body": body}
        if "option=com_fields&view=fields" in url:
            return {
                "status": 200,
                "body": (
                    f'<input type="hidden" name="{TOKEN}" value="1">'
                    '<a href="/administrator/index.php?option=com_fields&amp;task=field.edit&amp;id=7'
                    '&amp;context=com_content.article" title="Edit ProofCMS XML marker TEST">'
                    "ProofCMS XML marker TEST</a>"
                ),
            }
        return {"status": 200, "body": ""}

    def request(self, url: str, method: str = "GET", data=None, **kwargs) -> dict:
        self.calls.append(f"{method} {url}")
        if "task=field.reload" in str(data):
            return {"status": 200, "body": f'<input type="hidden" name="{TOKEN}" value="1">'}
        if "task=field.save" in str(data):
            self.marker = _marker_from_data(data)
            text = data.decode() if isinstance(data, bytes) else str(data)
            title = urllib.parse.parse_qs(text).get("jform[title]", [""])[0]
            return {
                "status": 200,
                "final_url": "/administrator/index.php?option=com_fields&view=fields&context=com_content.article",
                "body": (
                    "Field saved"
                    '<a href="/administrator/index.php?option=com_fields&amp;task=field.edit&amp;id=7'
                    f'&amp;context=com_content.article" title="Edit {title}">'
                ),
            }
        if "task=fields.trash" in url:
            return {"status": 200, "body": "Field trashed"}
        if "task=fields.delete" in url:
            return {"status": 200, "body": "Field deleted"}
        return {"status": 200, "body": ""}


def test_129393_version_boundaries():
    assert media_rce.classify_version("4.0.0") == "LIKELY_VULNERABLE"
    assert media_rce.classify_version("5.4.10") == "LIKELY_VULNERABLE"
    assert media_rce.classify_version("5.4.11") == "PATCHED"
    assert media_rce.classify_version("6.0.0") == "LIKELY_VULNERABLE"
    assert media_rce.classify_version("6.2.0") == "LIKELY_VULNERABLE"
    assert media_rce.classify_version("6.2.1") == "PATCHED"
    assert media_rce.classify_version("3.10.12") == "NOT_AFFECTED"
    assert media_rce.classify_version(None) == "INCONCLUSIVE"


def test_129393_passive_result():
    vulnerable = media_rce.check("https://target.test", joomla_version="5.4.10")
    assert vulnerable.status == "LIKELY_VULNERABLE"
    assert vulnerable.exploit_available is True
    assert "5.4.11" in vulnerable.action

    patched = media_rce.check("https://target.test", joomla_version="5.4.11")
    assert patched.status == "PATCHED"

    unknown = media_rce.check("https://target.test")
    assert unknown.status == "INCONCLUSIVE"


def test_129393_safe_mode_does_not_send_probe():
    finding = media_rce.check(
        "https://target.test",
        joomla_version="5.4.10",
        run_exploit_check=True,
        exploit_mode="safe",
    )
    assert "requires the authenticated aggressive" in finding.detail


def test_129393_aggressive_probe_confirms_attribute_injection():
    fake = FakeClient(article_has_class=True)
    with (
        patch.object(media_rce, "HttpClient", return_value=fake),
        patch.object(media_rce, "joomla_admin_login", return_value=True),
    ):
        result = media_rce.run_aggressive_probe(
            "https://target.test", username="admin", password="pw"
        )
    assert result.status == "VULNERABLE"
    assert result.confidence == "CONFIRMED"
    assert result.evidence["xml_attribute_injected"] is True
    assert result.evidence["created_field_id"] == 7
    assert result.cleanup_verified is True
    assert "no code was executed" in result.detail


def test_129393_patched_control_does_not_confirm():
    fake = FakeClient(article_has_class=False)
    with (
        patch.object(media_rce, "HttpClient", return_value=fake),
        patch.object(media_rce, "joomla_admin_login", return_value=True),
    ):
        result = media_rce.run_aggressive_probe(
            "https://target.test", username="admin", password="pw"
        )
    assert result.status == "NOT_CONFIRMED"
    assert result.evidence["xml_attribute_injected"] is False
    assert result.cleanup_verified is True


def test_129393_aggressive_probe_needs_credentials():
    result = media_rce.run_aggressive_probe("https://target.test")
    assert result.status == "BLOCKED_EXTERNAL"
    assert result.exploit_ran is False


def test_129393_metadata_contract():
    meta = media_rce.metadata()
    assert meta["cve"] == "CVE-2026-129393"
    assert meta["cms"] == "joomla"
    assert meta["exploit_available"] is True
    assert meta["exploit_modes"] == ["aggressive"]
    assert meta["vulnerability_type"] == "Remote Code Execution"
    assert meta["affected_joomla_versions"] == ["4.0.0-5.4.10", "6.0.0-6.2.0"]
