"""Contract: every module advertising active exploit modes must have unit tests
and a disposition row in labs/VALIDATED.md.

CONFIRMED rows must point at a lab directory that exists. Every registered
check across all four registries must have a row — passive-only modules link
to what blocks active proof. Add all three in the same commit as the module
(see README Development).
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


def _all_registered_cves() -> list[tuple[str, str]]:
    """Return (cve_id, module_short_name) for every registered check."""
    found = []
    for package in REGISTRIES:
        registry = importlib.import_module(package)
        for cve_id, module_path in sorted(getattr(registry, "AVAILABLE_CVES", {}).items()):
            found.append((cve_id, module_path.split(".")[-1]))
    return found


def _validation_rows() -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in (REPO / "labs" / "VALIDATED.md").read_text(encoding="utf-8").splitlines():
        match = re.match(r"\|\s*(CVE-\d+-\d+|WPVDB-[0-9a-f-]+|PROOFCMS-[A-Z0-9-]+)\b", line)
        if match:
            rows.setdefault(match.group(1), line)
    return rows


def _lab_from_row(row: str) -> str:
    """Return the labs/ directory referenced by a row, or ''."""
    for cell in (c.strip() for c in row.strip().strip("|").split("|")):
        cleaned = cell.strip("`").strip()
        if cleaned.startswith("labs/"):
            return cleaned
    return ""


class TestModuleContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = _active_modules()
        cls.all_cves = _all_registered_cves()
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

    def test_confirmed_rows_have_lab_directory(self):
        missing: list[str] = []
        for cve_id, short in self.modules:
            row = self.rows.get(cve_id)
            if row is None:
                continue
            cols = [c.strip() for c in row.strip().strip("|").split("|")]
            disposition = cols[3] if len(cols) >= 4 else ""
            if not re.search(r"(?<![A-Z_])CONFIRMED", disposition):
                continue
            lab = _lab_from_row(row)
            if not lab:
                missing.append(f"{cve_id} ({short}): CONFIRMED without a Lab entry")
            elif not (REPO / lab).is_dir():
                missing.append(f"{cve_id} ({short}): lab dir missing: {lab}")
        self.assertEqual(
            missing,
            [],
            "CONFIRMED rows must point at an existing labs/ directory:\n"
            + "\n".join(missing),
        )

    def test_all_registered_cves_have_validation_row(self):
        missing = [
            f"{cve_id} ({short})"
            for cve_id, short in self.all_cves
            if cve_id not in self.rows
        ]
        self.assertEqual(
            missing,
            [],
            "registered checks without a labs/VALIDATED.md row "
            "(passive-only modules must link to what blocks active proof):\n"
            + "\n".join(missing),
        )


if __name__ == "__main__":
    unittest.main()
