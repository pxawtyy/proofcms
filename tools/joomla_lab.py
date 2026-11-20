"""Deterministic Joomla lab runner driven by a declarative ``lab.json``.

The per-CVE ``compose.yml`` and seed scripts stay where they are; this tool
removes the repeated shell round-trips around them:

    python tools/joomla_lab.py up labs/cve-2026-75949
    python tools/joomla_lab.py seed labs/cve-2026-75949
    python tools/joomla_lab.py snapshot labs/cve-2026-75949
    python tools/joomla_lab.py validate labs/cve-2026-75949 --pretty
    python tools/joomla_lab.py reset labs/cve-2026-75949
    python tools/joomla_lab.py down labs/cve-2026-75949

``lab.json`` (shared schema, see ``.agents/labs.md``)::

    {
      "cms": "joomla",
      "compose": "compose.yml",
      "url": "http://127.0.0.1:8103",
      "control": "http://127.0.0.1:8104",
      "web": "joomla621",
      "control_web": "joomla624",
      "seed": [{"script": "seed.ps1", "timeout": 1800}],
      "databases": [{"service": "db621", "name": "joomla", "root_password": "root"}],
      "cleanup": [{"service": "joomla621", "command": ["sh", "-c", "..."]}],
      "proofs": {
        "CVE-2026-75949": {
          "mode": "aggressive",
          "args": ["--aggressive-arg", "canary=tmp/proofcms-jbd-canary.txt"]
        }
      }
    }
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

from _lab_util import (
    clean,
    compact,
    compose,
    dump_database,
    exec_service,
    load_lab,
    php_errors,
    proof_for,
    restore_database,
    run,
    run_proofcms,
    wait_http,
    wait_service_file,
)


def _compose_file(lab_dir: Path, config: dict[str, Any]) -> Path:
    return (lab_dir / str(config.get("compose", "compose.yml"))).resolve()


def _databases(config: dict[str, Any]) -> list[dict[str, Any]]:
    databases = config.get("databases") or []
    if not isinstance(databases, list):
        raise SystemExit("invalid lab.json: databases must be a list")
    return databases


def up(lab_dir: Path, config: dict[str, Any], quiet: bool = False) -> None:
    compose_file = _compose_file(lab_dir, config)
    result = compose(compose_file, "up", "-d", "--wait")
    if result.returncode != 0:
        raise SystemExit(clean(result.stderr) or clean(result.stdout))
    web = config.get("web")
    if web and config.get("wait_for_install", True) and not wait_service_file(
        compose_file,
        str(web),
        "/var/www/html/configuration.php",
        int(config.get("wait_timeout", 300)),
    ):
        raise SystemExit(f"{web} did not finish installing (missing configuration.php)")
    url = config.get("url")
    if url and not wait_http(str(url), int(config.get("wait_timeout", 300))):
        raise SystemExit(f"{url} did not answer")
    if not quiet:
        print(url)


def _shell() -> str:
    shell = shutil.which("powershell") or shutil.which("pwsh")
    if not shell:
        raise SystemExit("PowerShell not found; cannot run the lab seed script")
    return shell


def seed(lab_dir: Path, config: dict[str, Any], quiet: bool = False) -> None:
    compose_file = _compose_file(lab_dir, config)
    entries = config.get("seed") or []
    if not isinstance(entries, list):
        raise SystemExit("invalid lab.json: seed must be a list")
    for entry in entries:
        if isinstance(entry, dict) and entry.get("script"):
            script = (lab_dir / str(entry["script"])).resolve()
            if not script.exists():
                raise SystemExit(f"seed script not found: {script}")
            result = run(
                [_shell(), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)],
                cwd=lab_dir,
                timeout=int(entry.get("timeout", 1800)),
            )
            label = script.name
        elif isinstance(entry, dict) and entry.get("service"):
            command = entry.get("command")
            if not isinstance(command, list):
                raise SystemExit("lab.json seed entries need a command list")
            result = exec_service(compose_file, str(entry["service"]), *[str(part) for part in command])
            label = f"{entry['service']}: {' '.join(str(part) for part in command)}"
        elif isinstance(entry, str):
            result = exec_service(compose_file, str(config.get("web", "joomla")), "sh", "-c", entry)
            label = entry
        else:
            raise SystemExit("invalid lab.json seed entry")
        if result.returncode != 0:
            raise SystemExit(clean(result.stderr) or clean(result.stdout) or f"seed failed: {label}")
        if not quiet:
            print(f"seed: {label}")


def snapshot(lab_dir: Path, config: dict[str, Any], quiet: bool = False) -> None:
    compose_file = _compose_file(lab_dir, config)
    target_dir = lab_dir / ".snapshots"
    databases = _databases(config)
    if not databases:
        raise SystemExit("lab.json declares no databases to snapshot")
    written = []
    for database in databases:
        target = target_dir / f"{database['service']}.sql"
        dump_database(
            compose_file,
            str(database["service"]),
            str(database.get("name", "joomla")),
            str(database.get("root_password", "root")),
            target,
        )
        written.append(str(target))
    if not quiet:
        print(json.dumps({"snapshot": written}))


def reset(lab_dir: Path, config: dict[str, Any], quiet: bool = False) -> None:
    compose_file = _compose_file(lab_dir, config)
    for database in _databases(config):
        restore_database(
            compose_file,
            str(database["service"]),
            str(database.get("root_password", "root")),
            lab_dir / ".snapshots" / f"{database['service']}.sql",
        )
    for entry in config.get("cleanup") or []:
        if not isinstance(entry, dict) or not isinstance(entry.get("command"), list):
            raise SystemExit("invalid lab.json cleanup entry")
        result = exec_service(compose_file, str(entry["service"]), *[str(part) for part in entry["command"]])
        if result.returncode != 0:
            raise SystemExit(clean(result.stderr) or clean(result.stdout) or "cleanup failed")
    if not quiet:
        print("reset")


def validate(
    lab_dir: Path,
    config: dict[str, Any],
    cve: str | None,
    seed_lab: bool,
    pretty: bool,
) -> int:
    compose_file = _compose_file(lab_dir, config)
    proof = proof_for(config, cve)
    selected = str(proof.get("_cve") or cve or "")
    if not selected:
        raise SystemExit("select a CVE with --cve")
    up(lab_dir, config, quiet=True)
    if seed_lab:
        seed(lab_dir, config, quiet=True)
        if config.get("databases"):
            # Capture the seeded state so reset() is useful during iteration.
            snapshot(lab_dir, config, quiet=True)
    url = str(proof.get("url") or config.get("url") or "")
    control = proof.get("control") or config.get("control")
    if not url:
        raise SystemExit("lab.json has no url for the vulnerable stack")
    mode = str(proof.get("mode", "aggressive"))
    args = list(proof.get("args") or proof.get("proofcms_args") or [])
    timeout = int(proof.get("timeout", config.get("timeout", 120)))

    vulnerable = run_proofcms(selected, url, "joomla", mode, args, timeout)
    patched = None
    if control:
        patched = run_proofcms(selected, str(control), "joomla", mode, args, timeout)

    errors: list[str] = []
    if vulnerable.get("state") != "VULNERABLE" or (patched and patched.get("state") == "VULNERABLE"):
        for service in (config.get("web"), config.get("control_web")):
            if service:
                errors.extend(php_errors(compose_file, str(service)))
    result = compact(selected, vulnerable, patched, errors)
    print(json.dumps(result, indent=2 if pretty else None))
    return 0 if result["verdict"] == "CONFIRMED_WITH_CONTROL" else 2


def status(lab_dir: Path, config: dict[str, Any]) -> None:
    compose_file = _compose_file(lab_dir, config)
    result = compose(compose_file, "ps")
    print(clean(result.stdout or result.stderr))
    url = config.get("url")
    if url:
        print(f"vulnerable: {url} reachable={wait_http(str(url), timeout=10)}")
    control = config.get("control")
    if control:
        print(f"control:    {control} reachable={wait_http(str(control), timeout=10)}")


def down(lab_dir: Path, config: dict[str, Any], keep_snapshot: bool = False) -> None:
    compose(_compose_file(lab_dir, config), "down", "-v")
    if not keep_snapshot:
        snapshots = lab_dir / ".snapshots"
        if snapshots.exists():
            shutil.rmtree(snapshots)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("up", "seed", "snapshot", "reset", "status"):
        command = sub.add_parser(name)
        command.add_argument("lab", help="Lab directory or lab.json path")
    down_parser = sub.add_parser("down")
    down_parser.add_argument("lab", help="Lab directory or lab.json path")
    down_parser.add_argument("--keep-snapshot", action="store_true")

    validate_parser = sub.add_parser("validate")
    validate_parser.add_argument("lab", help="Lab directory or lab.json path")
    validate_parser.add_argument("--cve", help="Select a proof when lab.json defines several")
    validate_parser.add_argument("--no-seed", action="store_true")
    validate_parser.add_argument("--pretty", action="store_true")

    args = parser.parse_args()
    lab_dir, config = load_lab(args.lab)
    if config.get("cms", "joomla") != "joomla":
        raise SystemExit("joomla_lab only runs joomla lab.json files")
    if args.command == "up":
        up(lab_dir, config)
    elif args.command == "seed":
        seed(lab_dir, config)
    elif args.command == "snapshot":
        snapshot(lab_dir, config)
    elif args.command == "reset":
        reset(lab_dir, config)
    elif args.command == "status":
        status(lab_dir, config)
    elif args.command == "down":
        down(lab_dir, config, args.keep_snapshot)
    elif args.command == "validate":
        return validate(lab_dir, config, args.cve, not args.no_seed, args.pretty)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
