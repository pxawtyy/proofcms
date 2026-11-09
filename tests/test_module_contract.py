"""Contract: every module advertising active exploit modes must have unit tests
and a disposition row in labs/VALIDATED.md.

Add both in the same commit as the module (see README Development).
"""

from __future__ import annotations

import importlib
import pathlib
import re
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent
REGISTRIES = (
    "proofcms.modules.wordpress",
    "proofcms.modules.joomla",
    "proofcms.modules.generic",
    "proofcms.modules.php",
)
DISPOSITIONS = (
    "CONFIRMED",
    "NOT_CONFIRMED",
    "BLOCKED_EXTERNAL",
    "NOT_YET_VALIDATED",
    "AGGRESSIVE_SENT",
)


def _active_modules() -> list[tuple[str, str]]:
    """Return (cve_id, module_short_name) for modules with exploit modes."""
    found = []
    for package in REGISTRIES:
        registry = importlib.import_module(package)
        for cve_id, module_path in sorted(getattr(registry, "AVAILABLE_CVES", {}).items()):
            module = importlib.import_module(module_path)
            if module.metadata().get("exploit_modes"):
                found.append((cve_id, module_path.split(".")[-1]))
    return found


def _test_sources() -> dict[str, str]:
    return {
        path.name: path.read_text(encoding="utf-8", errors="replace")
        for path in sorted((REPO / "tests").glob("test_*.py"))
    }


def _validation_rows() -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in (REPO / "labs" / "VALIDATED.md").read_text(encoding="utf-8").splitlines():
        match = re.match(r"\|\s*(CVE-\d+-\d+)\s*\|", line)
        if match:
            rows.setdefault(match.group(1), line)
    return rows


class TestModuleContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = _active_modules()
        cls.sources = _test_sources()
        cls.rows = _validation_rows()
        assert cls.modules, "no active modules discovered; registry wiring may be broken"

    def test_active_probe_modules_have_unit_tests(self):
        missing = []
        for cve_id, short in self.modules:
            pattern = re.compile(rf"\b{re.escape(short)}\b")
            if not any(pattern.search(source) for source in self.sources.values()):
                missing.append(f"{cve_id} ({short})")
        self.assertEqual(
            missing,
            [],
            "active probe modules without referencing unit tests (add tests alongside the module):\n"
            + "\n".join(missing),
        )

    def test_active_probe_modules_have_validation_row(self):
        missing: list[str] = []
        undispositioned: list[str] = []
        for cve_id, short in self.modules:
            row = self.rows.get(cve_id)
            if row is None:
                missing.append(f"{cve_id} ({short})")
            elif not any(disp in row for disp in DISPOSITIONS):
                undispositioned.append(f"{cve_id} ({short})")
        self.assertEqual(
            missing,
            [],
            "active probe modules without a labs/VALIDATED.md row (add one in the same commit):\n"
            + "\n".join(missing),
        )
        self.assertEqual(
            undispositioned,
            [],
            "validation rows without a recognized disposition "
            f"{DISPOSITIONS}:\n" + "\n".join(undispositioned),
        )


if __name__ == "__main__":
    unittest.main()
