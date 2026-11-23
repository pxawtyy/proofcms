from proofcms.redaction import _load_local_rules, scan_text


def test_flags_government_host():
    assert scan_text("https://" + "foo" + ".gov.br/app")


def test_flags_education_host():
    assert scan_text("https://" + "foo" + ".edu.br/app")


def test_allows_placeholders():
    assert not scan_text("https://target.example/portal/login.aspx")
    assert not scan_text("https://fixture.test/app")


def test_local_rules_are_opt_in(tmp_path, monkeypatch):
    config = tmp_path / "rules.json"
    config.write_text(
        '[{"name": "local-codename", "pattern": "\\\\bexample-codename\\\\b"}]',
        encoding="utf-8",
    )
    monkeypatch.setenv("PROOFCMS_REDACTION_RULES", str(config))
    rules = _load_local_rules()
    assert any(name == "local-codename" for name, _ in rules)


def test_violation_does_not_echo_the_value():
    violations = scan_text("https://" + "foo" + ".gov.br/app")
    assert violations
    assert "foo" not in repr(violations[0])
