"""Fail-fast verification for a change set.

Runs, in order, stopping at the first failure:

1. ``ruff check .``
2. targeted pytest for the changed modules (full suite for core changes)
3. ``tests/test_module_contract.py``
4. ``mypy proofcms tools``

Examples::

    python tools/verify.py              # changed files vs HEAD
    python tools/verify.py --full       # whole pytest suite
    python tools/verify.py --list       # show the selected tests
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CONTRACT = REPO / "tests" / "test_module_contract.py"
CORE_PREFIXES = (
    "proofcms/cli.py",
    "proofcms/core/",
    "proofcms/detectors/",
    "proofcms/reporting/",
    "proofcms/__init__.py",
)


def _git(*args: str) -> list[str]:
    result = subprocess.run(
        ["git", *args],
        cwd=str(REPO),
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return []
    return [item for item in result.stdout.decode("utf-8", "replace").split("\0") if item]


def changed_files() -> list[str]:
    tracked = _git("diff", "--name-only", "-z", "HEAD")
    untracked = _git("ls-files", "-z", "--others", "--exclude-standard")
    return sorted({path.replace("\\", "/") for path in tracked + untracked})


def _cve_from_stem(stem: str) -> str | None:
    parts = stem.split("_")
    if len(parts) >= 4 and parts[0] == "cve" and parts[1].isdigit() and parts[2].isdigit():
        return f"CVE-{parts[1]}-{parts[2]}"
    return None


def targeted_tests(changed: list[str]) -> list[Path]:
    tests = sorted((REPO / "tests").glob("test_*.py"))
    if any(path.startswith(CORE_PREFIXES) for path in changed):
        return []
    selected: set[Path] = set()
    for path in changed:
        candidate = Path(path)
        if path.startswith("tests/") and candidate.name.startswith("test_") and candidate.suffix == ".py":
            selected.add(REPO / candidate)
            continue
        if not path.startswith("proofcms/modules/"):
            continue
        cve = _cve_from_stem(candidate.stem)
        needle = cve or candidate.stem
        for test in tests:
            try:
                text = test.read_text(encoding="utf-8")
            except OSError:
                continue
            if needle in text or candidate.stem in test.name:
                selected.add(test)
    return sorted(selected)


def run_step(name: str, cmd: list[str]) -> int:
    print(f"\n==> {name}: {' '.join(cmd)}", flush=True)
    started = time.perf_counter()
    result = subprocess.run(cmd, cwd=str(REPO), check=False)
    elapsed = time.perf_counter() - started
    print(f"<== {name}: exit {result.returncode} in {elapsed:.1f}s", flush=True)
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", action="store_true", help="Run the whole pytest suite")
    parser.add_argument("--list", action="store_true", help="List the selected tests and exit")
    args = parser.parse_args()

    changed = changed_files()
    tests = [] if args.full else targeted_tests(changed)
    if args.list:
        print("changed files:")
        for path in changed:
            print(f"  {path}")
        print("pytest targets:")
        for test in tests or [REPO / "tests"]:
            print(f"  {test.relative_to(REPO)}")
        return 0

    steps: list[tuple[str, list[str]]] = [
        ("ruff", [sys.executable, "-m", "ruff", "check", "."]),
    ]
    code_changed = any(path.startswith(("proofcms/", "tests/")) for path in changed)
    if args.full or (code_changed and not tests):
        steps.append(("pytest", [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"]))
    elif tests:
        steps.append(
            (
                "pytest",
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                    "-p",
                    "no:cacheprovider",
                    *[str(test.relative_to(REPO)) for test in tests],
                ],
            )
        )
    steps.append(
        (
            "contract",
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(CONTRACT.relative_to(REPO))],
        )
    )
    steps.append(("mypy", [sys.executable, "-m", "mypy", "proofcms", "tools"]))

    for name, cmd in steps:
        code = run_step(name, cmd)
        if code != 0:
            print(f"\nFAILED at {name}", flush=True)
            return code
    print("\nall checks passed", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
