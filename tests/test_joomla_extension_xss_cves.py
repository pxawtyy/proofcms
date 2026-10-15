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
