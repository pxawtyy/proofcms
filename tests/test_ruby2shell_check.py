from __future__ import annotations

import json

from proofcms.ruby2shell import (
    Verdict,
    check,
    classify_version,
    main,
    parse_ruby_version,
    probe_legacy_encoding,
    read_ruby_version,
)

RUBY_3412 = "ruby 3.4.12 (2026-10-23 revision 366f5fdc00) +PRISM [x86_64-linux]"
RUBY_3413 = "ruby 3.4.13 (2026-11-19 revision 48857d6f2e) +PRISM [x86_64-linux]"
RUBY_3313 = "ruby 3.3.13 (2026-10-23 revision 1f3e2c6) [x86_64-linux]"
RUBY_3314 = "ruby 3.3.14 (2026-11-18 revision abcdef0) [x86_64-linux]"
RUBY_409 = "ruby 4.0.9 (2026-11-01 revision 1234567) +PRISM [x86_64-linux]"
RUBY_4010 = "ruby 4.0.10 (2026-11-18 revision 89abcde) +PRISM [x86_64-linux]"
RUBY_2610 = "ruby 2.6.10p210 (2022-04-12 revision 67958) [universal.x86_64-darwin21]"


def test_parse_ruby_version() -> None:
    info = parse_ruby_version(RUBY_3412)
    assert info is not None
    assert info.version == "3.4.12"
    assert info.numbers == (3, 4, 12)
    assert info.platform == "x86_64-linux"


def test_parse_bare_version_and_patchlevel() -> None:
    info = parse_ruby_version(RUBY_2610)
    assert info is not None
    assert info.numbers == (2, 6, 10)
    bare = parse_ruby_version("3.4.12")
    assert bare is not None
    assert bare.numbers == (3, 4, 12)


def test_classify_affected_and_fixed() -> None:
    assert classify_version(parse_ruby_version(RUBY_3412)) == Verdict.AFFECTED
    assert classify_version(parse_ruby_version(RUBY_3413)) == Verdict.PATCHED
    assert classify_version(parse_ruby_version(RUBY_3313)) == Verdict.AFFECTED
    assert classify_version(parse_ruby_version(RUBY_3314)) == Verdict.PATCHED
    assert classify_version(parse_ruby_version(RUBY_409)) == Verdict.AFFECTED
    assert classify_version(parse_ruby_version(RUBY_4010)) == Verdict.PATCHED
    assert classify_version(parse_ruby_version(RUBY_2610)) == Verdict.EOL_AFFECTED
    assert classify_version(None) == Verdict.UNKNOWN


def test_check_without_probe() -> None:
    result = check(RUBY_3412, probe=False)
    assert result.verdict == Verdict.AFFECTED
    assert result.legacy_encoding is None
    fixed = check(RUBY_3413, probe=False)
    assert fixed.verdict == Verdict.PATCHED


def test_probe_unavailable_ruby() -> None:
    assert probe_legacy_encoding("definitely-not-a-ruby-binary") is None
    assert read_ruby_version("definitely-not-a-ruby-binary") is None


def test_main_json(capsys) -> None:
    code = main(["--version-string", RUBY_3412, "--json"])
    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["cve"] == "CVE-2026-132825"
    assert payload["verdict"] == "AFFECTED"
    assert payload["ruby"]["numbers"] == [3, 4, 12]


def test_main_patched_exit(capsys) -> None:
    code = main(["--version-string", RUBY_3413])
    assert code == 0
    assert "verdict: PATCHED" in capsys.readouterr().out
