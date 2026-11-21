"""Contract: every module advertising active exploit modes must have unit tests
and a disposition row in labs/VALIDATED.md.

CONFIRMED rows must point at a lab directory that exists. Every registered
check across all four registries must have a row - passive-only modules link
to what blocks active proof - and every registered check must also appear in
docs/CVE-INDEX.md. Add all of them in the same commit as the module (see
README Development).
"""

from __future__ import annotations

import ast
import contextlib
import importlib
import pathlib
import re
import unittest
from unittest.mock import patch

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
DEDICATED_JOOMLA_DETECTORS = {
    "icagenda",
    "baforms",
    "gridbox",
    "sppagebuilder",
    "jbusinessdirectory",
    "pagebuilderck",
    "rsfiles",
    "helix3",
    "helixultimate",
}
NOT_FOUND_RESPONSE = {
    "status": 404,
    "body": "Not Found",
    "headers": {},
    "headers_multi": {},
    "final_url": "https://fixture.test/",
    "url": "https://fixture.test/",
    "requested_url": "https://fixture.test/",
    "body_hash": "not-found",
    "normalized_body_hash": "not-found",
    "body_len": 9,
    "title": "",
    "error": None,
    "truncated": False,
    "captured_bytes": 9,
}


class _NotFoundClient:
    def __init__(self, *args, **kwargs):
        pass

    def get(self, *args, **kwargs):
        return dict(NOT_FOUND_RESPONSE)

    def request(self, *args, **kwargs):
        return dict(NOT_FOUND_RESPONSE)

    def post(self, *args, **kwargs):
        return dict(NOT_FOUND_RESPONSE)

    def post_multipart(self, *args, **kwargs):
        return dict(NOT_FOUND_RESPONSE)


def _not_found_request(*args, **kwargs):
    return dict(NOT_FOUND_RESPONSE)


def _registered_modules() -> list[tuple[str, str, object, str]]:
    """Return (cve_id, module_path, module, registry_cms)."""
    found = []
    for package in REGISTRIES:
        registry = importlib.import_module(package)
        cms = package.rsplit(".", 1)[-1]
        for cve_id, module_path in sorted(getattr(registry, "AVAILABLE_CVES", {}).items()):
            module = importlib.import_module(module_path)
            found.append((cve_id, module_path, module, cms))
    return found


def _is_core_module(meta: dict) -> bool:
    component = str(meta.get("component") or "").lower()
    name = str(meta.get("name") or "").lower()
    return "core" in component or "core" in name


def _literal_strings(node: ast.AST) -> list[str]:
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return [
            element.value
            for element in node.elts
            if isinstance(element, ast.Constant) and isinstance(element.value, str)
        ]
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    return []


def _receiver_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.BoolOp):
        names: set[str] = set()
        for value in node.values:
            names |= _receiver_names(value)
        return names
    if isinstance(node, ast.Attribute):
        return _receiver_names(node.value)
    return set()


def _detector_keys_from_source(source: str) -> tuple[set[str], set[str]]:
    tree = ast.parse(source)
    declared: set[str] = set()
    consulted: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and target.id in {
                    "PLUGIN_KEYS",
                    "DETECTOR_KEYS",
                    "PLUGIN_SLUG",
                }:
                    declared.update(_literal_strings(node.value))
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and node.args
            and (_receiver_names(node.func.value) & {"plugins", "extensions"})
        ):
            consulted.update(_literal_strings(node.args[0]))
    return declared, consulted


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


def _lab_from_row(row: str) -> list[str]:
    """Return all labs/ directories referenced by a row."""
    return re.findall(r"labs/[A-Za-z0-9_.-]+", row)


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
            labs = _lab_from_row(row)
            if not labs:
                missing.append(f"{cve_id} ({short}): CONFIRMED without a Lab entry")
            else:
                gone = [lab for lab in labs if not (REPO / lab).is_dir()]
                if gone:
                    missing.append(f"{cve_id} ({short}): lab dir missing: {', '.join(gone)}")
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

    def test_all_registered_cves_have_index_row(self):
        index_text = (REPO / "docs" / "CVE-INDEX.md").read_text(encoding="utf-8")
        index_ids = set(re.findall(r"^\| `([^`]+)`", index_text, re.MULTILINE))
        registered = {cve_id for cve_id, _ in self.all_cves}
        missing = sorted(registered - index_ids)
        extra = sorted(index_ids - registered)
        self.assertEqual(
            missing,
            [],
            "registered checks missing from docs/CVE-INDEX.md "
            "(add a row in the same commit as the module):\n" + "\n".join(missing),
        )
        self.assertEqual(
            extra,
            [],
            "docs/CVE-INDEX.md rows that are not registered checks "
            "(remove or fix the identifier):\n" + "\n".join(extra),
        )

    def test_non_core_modules_are_silent_on_404(self):
        """A 404-only target must never yield a non-core finding.

        This is the regression guard for the cross-version false positives:
        non-core modules must use their own detector/runtime evidence and
        treat a missing manifest/readme as NOT_DETECTED, even when a CMS core
        version (3.9.0 here) is present.
        """
        failures: list[str] = []
        for cve_id, module_path, module, _registry_cms in _registered_modules():
            meta = module.metadata()
            if _is_core_module(meta):
                continue
            with contextlib.ExitStack() as stack:
                for attr, replacement in (
                    ("HttpClient", _NotFoundClient),
                    ("HttpSession", _NotFoundClient),
                    ("request", _not_found_request),
                    ("fetch_url", _not_found_request),
                ):
                    if hasattr(module, attr):
                        stack.enter_context(patch.object(module, attr, replacement))
                try:
                    result = module.check(
                        "https://fixture.test",
                        cms_version="3.9.0",
                        run_exploit_check=False,
                        timeout=1,
                        proxy=None,
                        plugins={},
                        php_runtime={"detected": False},
                        nginx_runtime={"detected": False},
                        node_runtime={"detected": False},
                        aspnet_runtime={"detected": False},
                    )
                except Exception as exc:  # noqa: BLE001 - report the module, keep scanning
                    failures.append(f"{cve_id} ({module_path}): {type(exc).__name__}: {exc}")
                    continue
            if result.status != "NOT_DETECTED":
                failures.append(
                    f"{cve_id} ({module_path}): {result.status} - {result.detail[:140]}"
                )
        self.assertEqual(
            failures,
            [],
            "non-core modules must return NOT_DETECTED when every public artifact is 404:\n"
            + "\n".join(failures),
        )

    def test_plugin_detector_keys_align_with_detectors(self):
        """Every plugin/extension lookup must name a real detector key."""
        from proofcms.detectors.joomla import COMMON_COMPONENTS
        from proofcms.detectors.wordpress import KNOWN_PLUGIN_MARKERS

        allowed_wordpress = set(KNOWN_PLUGIN_MARKERS)
        allowed_joomla = set(COMMON_COMPONENTS) | DEDICATED_JOOMLA_DETECTORS
        violations: list[str] = []
        for cve_id, module_path, module, registry_cms in _registered_modules():
            source = pathlib.Path(module.__file__).read_text(encoding="utf-8", errors="replace")
            declared, consulted = _detector_keys_from_source(source)
            if not declared and not consulted:
                continue
            meta = module.metadata()
            cms = meta.get("cms") or registry_cms
            if cms == "wordpress":
                allowed = allowed_wordpress
            elif cms == "joomla":
                allowed = allowed_joomla
            else:
                continue
            effective = declared | consulted
            if not (effective & allowed):
                violations.append(
                    f"{cve_id} ({module_path}): no key matches a detector; "
                    f"declared={sorted(declared)} consulted={sorted(consulted)}"
                )
            unknown = consulted - allowed - declared
            if unknown:
                violations.append(
                    f"{cve_id} ({module_path}): consulted but undeclared keys {sorted(unknown)}"
                )
        self.assertEqual(
            violations,
            [],
            "module plugin/extension keys must exist in the WordPress markers or Joomla detectors:\n"
            + "\n".join(violations),
        )

    def test_upload_modules_have_cleanup_hook(self):
        """Any module that reports an uploaded file or writes one needs cleanup()."""
        from proofcms.cli import cleanup_capable_cves

        capable = set(cleanup_capable_cves())
        write_markers = ("move_uploaded_file", "file_put_contents", "fopen(", "fwrite(", "unlink(")
        missing: list[str] = []
        for cve_id, module_path, module, _registry_cms in _registered_modules():
            source = pathlib.Path(module.__file__).read_text(encoding="utf-8", errors="replace")
            meta = module.metadata()
            modes = set(meta.get("exploit_modes") or [])
            needs_cleanup = "uploaded_filename" in source or (
                "aggressive" in modes and any(marker in source for marker in write_markers)
            )
            if not needs_cleanup:
                continue
            if not callable(getattr(module, "cleanup", None)) or cve_id not in capable:
                missing.append(f"{cve_id} ({module_path})")
        self.assertEqual(
            missing,
            [],
            "modules that upload/write files must expose a valid cleanup() hook:\n"
            + "\n".join(missing),
        )


if __name__ == "__main__":
    unittest.main()
