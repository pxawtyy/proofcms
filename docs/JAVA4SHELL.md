# Java4Shell inventory check (CVE-2026-114938)

`tools/java4shell_check.py` checks a local JVM and CPU against the two
conditions for Java4Shell. It is an inventory helper: it parses
`java -version` and the CPU flags and never sends malformed input.

## Usage

```bash
# Linux/WSL: reads /proc/cpuinfo
python tools/java4shell_check.py

# JSON for automation
python tools/java4shell_check.py --json

# Explicit inputs (useful on Windows or for a remote inventory)
python tools/java4shell_check.py \
  --version-string 'openjdk version "17.0.13" 2025-01-21' \
  --cpu-flags "avx512f avx512bw avx512vbmi bmi2"
```

On Windows, `/proc/cpuinfo` is absent; pass `--cpu-flags` or run the checker on
the Linux host.

## Verdicts

| Verdict | Meaning |
|---|---|
| `AFFECTED` | Affected version and all four AVX-512 flags present. |
| `PATCHED` | Version is at or above the fixed build for its branch. |
| `NOT_AFFECTED_VERSION` | Version is outside the affected branches. |
| `NOT_AFFECTED_HARDWARE` | Affected version, but at least one AVX-512 flag is missing. |
| `MITIGATED` | Affected version and hardware, but a mitigation flag is present in the JVM option environment. |
| `UNKNOWN` | Java 11 advisory range, missing `java`, or CPU flags unavailable. |

## Version matrix

| Branch | Affected | Fixed |
|---|---|---|
| OpenJDK 17 | 17.0.6 through 17.0.21.0 | 17.0.21.1 |
| OpenJDK 21 | 21.0.0 through 21.0.13.0 | 21.0.13.1 |
| OpenJDK 25 | 25.0.0 through 25.0.5.0 | 25.0.5.1 |
| OpenJDK 27 | 27.0.0 through 27.0.1.0 | 27.0.1.1 |
| Oracle Java 8 | 8u511b33-perf | 8u513 |
| OpenJDK 11 | vendor advisory | 11.0.33.1 |

The hardware condition is `avx512f`, `avx512bw`, `avx512vbmi` and `bmi2`; ARM
is not affected.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | `PATCHED`, `NOT_AFFECTED_VERSION`, `NOT_AFFECTED_HARDWARE` or `MITIGATED` |
| `1` | `AFFECTED` |
| `2` | `UNKNOWN` |

## Notes

- A mitigation is only reported when `-XX:-UseBASE64Intrinsics` or
  `-XX:UseAVX=2` appears in `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS` or
  `_JAVA_OPTIONS`. The flag must be applied to the target JVM.
- The PoC lab for an AVX-512 host is `labs/cve-2026-114938`.
