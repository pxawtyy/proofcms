from proofcms.redaction import scan_text


def test_flags_government_host():
    assert scan_text("https://" + "foo" + ".gov.br/app")


def test_flags_education_host():
    assert scan_text("https://" + "foo" + ".edu.br/app")


def test_flags_target_codename():
    assert scan_text("/" + "fa" + "tec/login.aspx")


def test_flags_vendor_build():
    assert scan_text("build " + "10_1_8-" + "12345")


def test_allows_placeholders():
    assert not scan_text("https://target.example/portal/login.aspx")
    assert not scan_text("https://fixture.test/app")


def test_violation_does_not_echo_the_value():
    violations = scan_text("https://" + "foo" + ".gov.br/app")
    assert violations
    assert "foo" not in repr(violations[0])
