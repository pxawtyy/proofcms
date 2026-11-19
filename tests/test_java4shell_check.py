from __future__ import annotations

import json

from proofcms.java4shell import (
    REQUIRED_FLAGS,
    Verdict,
    check,
    classify_version,
    main,
    parse_cpu_flags,
    parse_java_version,
)

OPENJDK_17 = (
    'openjdk version "17.0.13" 2025-01-21\n'
    "OpenJDK Runtime Environment Temurin-17.0.13+11 (build 17.0.13+11)"
)
OPENJDK_17_FIXED = 'openjdk version "17.0.21.1" 2026-11-17'
JDK_21 = 'java version "21.0.10" 2026-01-20 LTS'
JDK_21_FIXED = 'java version "21.0.13.1" 2026-11-17'
JAVA_8 = (
    'java version "1.8.0_511"\n'
    "Java(TM) SE Runtime Environment (build 1.8.0_511-b33)"
)
JAVA_8_FIXED = 'java version "1.8.0_513"'
JDK_11_OLD = 'openjdk version "11.0.32" 2025-10-21'
JDK_11_FIXED = 'openjdk version "11.0.33.1" 2026-11-17'


def test_parse_openjdk_version() -> None:
    info = parse_java_version(OPENJDK_17)
    assert info is not None
    assert info.version == "17.0.13"
    assert info.numbers == (17, 0, 13)
    assert info.vendor == "openjdk"


def test_parse_java8_version() -> None:
    info = parse_java_version(JAVA_8)
    assert info is not None
    assert info.numbers == (8, 0, 511)
    assert info.vendor == "oracle"


def test_classify_affected_and_fixed() -> None:
    assert classify_version(parse_java_version(OPENJDK_17)) == Verdict.AFFECTED
    assert classify_version(parse_java_version(OPENJDK_17_FIXED)) == Verdict.PATCHED
    assert classify_version(parse_java_version(JDK_21)) == Verdict.AFFECTED
    assert classify_version(parse_java_version(JDK_21_FIXED)) == Verdict.PATCHED
    assert classify_version(parse_java_version(JAVA_8)) == Verdict.AFFECTED
    assert classify_version(parse_java_version(JAVA_8_FIXED)) == Verdict.PATCHED
    assert classify_version(parse_java_version(JDK_11_OLD)) == Verdict.UNKNOWN
    assert classify_version(parse_java_version(JDK_11_FIXED)) == Verdict.PATCHED


def test_cpu_flags() -> None:
    text = "processor : 0\nflags : fpu avx512f avx512bw avx512vbmi bmi2\n"
    assert parse_cpu_flags(text) >= REQUIRED_FLAGS
    assert parse_cpu_flags("processor : 0\nflags : fpu avx2\n") == frozenset({"fpu", "avx2"})


def test_check_affected() -> None:
    result = check(OPENJDK_17, REQUIRED_FLAGS)
    assert result.verdict == Verdict.AFFECTED
    assert result.missing_flags == ()


def test_check_hardware_blocked() -> None:
    flags = frozenset({"avx512f"})
    result = check(OPENJDK_17, flags)
    assert result.verdict == Verdict.NOT_AFFECTED_HARDWARE
    assert set(result.missing_flags) == REQUIRED_FLAGS - flags


def test_check_patched() -> None:
    result = check(OPENJDK_17_FIXED, REQUIRED_FLAGS)
    assert result.verdict == Verdict.PATCHED


def test_check_mitigated() -> None:
    result = check(
        OPENJDK_17,
        REQUIRED_FLAGS,
        {"JAVA_TOOL_OPTIONS": "-XX:-UseBASE64Intrinsics"},
    )
    assert result.verdict == Verdict.MITIGATED


def test_check_unknown_hardware() -> None:
    result = check(OPENJDK_17, None)
    assert result.verdict == Verdict.UNKNOWN


def test_cli_json(capsys) -> None:
    code = main(
        [
            "--version-string",
            OPENJDK_17,
            "--cpu-flags",
            "avx512f avx512bw avx512vbmi bmi2",
            "--json",
        ]
    )
    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "AFFECTED"
    assert payload["java"]["version"] == "17.0.13"
