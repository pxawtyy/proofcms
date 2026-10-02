from unittest.mock import patch

from proofcms.modules.joomla import cve_2015_8562


def test_cve_2015_8562_uses_harmless_default_command():
    with (
        patch.object(cve_2015_8562, "generate_payload", return_value="serialized") as generator,
        patch.object(cve_2015_8562, "send_payload", return_value=[200, 200, 200, 200]),
    ):
        result = cve_2015_8562.check(
            "http://target.test",
            "2.5.7",
            run_exploit_check=True,
            exploit_mode="aggressive",
        )

    assert result.status == "AGGRESSIVE_SENT"
    assert result.exploit_ran is True
    assert "uname -a (default)" in result.detail
    assert "uname -a" in generator.call_args.args[0]


def test_cve_2015_8562_preserves_custom_command():
    with (
        patch.object(cve_2015_8562, "generate_payload", return_value="serialized") as generator,
        patch.object(cve_2015_8562, "send_payload", return_value=[200] * 4),
    ):
        result = cve_2015_8562.check(
            "http://target.test",
            "2.5.7",
            run_exploit_check=True,
            exploit_mode="aggressive",
            aggressive_command="printf PROOFCMS",
        )

    assert result.status == "AGGRESSIVE_SENT"
    assert "custom command" in result.detail
    assert "printf PROOFCMS" in generator.call_args.args[0]
