"""Fast WordPress fixture runner for lab validation.

Reuses one pinned WordPress + MariaDB stack. The WP-CLI container is
long-running, so commands are ``docker compose exec`` (~200 ms) instead of
``docker compose run --rm`` (2-5 s each). A clean SQL + plugins snapshot makes
``reset`` a restore measured in seconds instead of a full rebuild.

Manual loop:

    python tools/wp_lab.py up
    python tools/wp_lab.py install https://downloads.wordpress.org/plugin/forminator.1.35.1.zip
    python -m proofcms -u http://127.0.0.1:9212 --cve CVE-2024-10402 ...
    python tools/wp_lab.py reset
    python tools/wp_lab.py install https://downloads.wordpress.org/plugin/forminator.1.36.0.zip
    python tools/wp_lab.py down

One-shot validation (compact JSON, vulnerable + patched control):

    python tools/wp_lab.py validate --cve CVE-2024-10402 \
      --vuln https://downloads.wordpress.org/plugin/forminator.1.35.1.zip \
      --patched https://downloads.wordpress.org/plugin/forminator.1.36.0.zip \
      --mode aggressive

Declarative form (see ``labs/cve-2024-10402/lab.json``):

    python tools/wp_lab.py run labs/cve-2024-10402 --pretty
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

from _lab_util import (
    REPO,
    cache_source,
    clean,
    compact,
    compose,
    dump_database,
    exec_bytes,
    exec_service,
    load_lab,
    php_errors,
    proof_for,
    restore_database,
    run_proofcms,
    wait_service_file,
)

COMPOSE = REPO / "labs" / "_wp-base" / "compose.yml"
SNAPSHOTS = REPO / "labs" / "_wp-base" / ".snapshots"
DB_SNAPSHOT = SNAPSHOTS / "wordpress.sql"
PLUGINS_SNAPSHOT = SNAPSHOTS / "plugins.tgz"
BASE = "http://127.0.0.1:9212"
ADMIN = "admin"
PASSWORD = "proofcms-lab-password"
EMAIL = "lab@example.test"
DB_NAME = "wordpress"
DB_ROOT_PASSWORD = "proofcms"
DEFAULT_CACHE = Path("D:/ProofCMS-Labs/cache") if Path("D:/ProofCMS-Labs").exists() else REPO / ".cache"


def _wp(*args: str) -> subprocess.CompletedProcess[str]:
    return exec_service(COMPOSE, "cli", "wp", *args, "--allow-root")


def _install_core() -> None:
    result = _wp(
        "core",
        "install",
        f"--url={BASE}",
        "--title=ProofCMS base",
        f"--admin_user={ADMIN}",
        f"--admin_password={PASSWORD}",
        f"--admin_email={EMAIL}",
        "--skip-email",
    )
    if result.returncode != 0 and _wp("core", "is-installed").returncode != 0:
        raise SystemExit(clean(result.stderr) or clean(result.stdout))
    _wp("rewrite", "structure", "/%postname%/", "--hard")
    _wp("rewrite", "flush", "--hard")


def _snapshot_ready() -> bool:
    return DB_SNAPSHOT.exists() and PLUGINS_SNAPSHOT.exists()


def snapshot(force: bool = False, quiet: bool = False) -> None:
    """Dump the database and the pristine plugin tree to the host cache."""
    if _snapshot_ready() and not force:
        if not quiet:
            print(json.dumps({"snapshot": str(SNAPSHOTS), "cached": True}))
        return
    dump_database(COMPOSE, "db", DB_NAME, DB_ROOT_PASSWORD, DB_SNAPSHOT)
    archived = exec_bytes(
        COMPOSE,
        "cli",
        "tar",
        "-C",
        "/var/www/html/wp-content",
        "-czf",
        "-",
        "plugins",
    )
    if archived.returncode != 0:
        raise SystemExit(clean(archived.stderr.decode("utf-8", "replace")) or "plugin snapshot failed")
    PLUGINS_SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
    PLUGINS_SNAPSHOT.write_bytes(archived.stdout)
    if not quiet:
        print(json.dumps({"snapshot": str(SNAPSHOTS), "cached": False}))


def up(quiet: bool = False) -> None:
    result = compose(COMPOSE, "up", "-d", "--wait")
    if result.returncode != 0:
        raise SystemExit(clean(result.stderr) or clean(result.stdout))
    if not wait_service_file(COMPOSE, "cli", "/var/www/html/wp-config.php", 180):
        raise SystemExit("wp-config.php did not appear; check docker compose logs wordpress")
    installed = _wp("core", "is-installed").returncode == 0
    if not installed:
        _install_core()
    # A fresh volume invalidates a cached snapshot (e.g. after down -v).
    snapshot(force=not installed, quiet=quiet)
    if not quiet:
        print(BASE)


def install(
    source: str,
    activate: bool = True,
    cache_dir: Path | str = DEFAULT_CACHE,
    quiet: bool = False,
) -> None:
    cached = cache_source(source, cache_dir)
    if not cached.exists():
        raise SystemExit(f"fixture not found: {cached}")
    remote = f"/tmp/{cached.name}"
    copied = compose(COMPOSE, "cp", str(cached), f"cli:{remote}")
    if copied.returncode != 0:
        raise SystemExit(clean(copied.stderr) or clean(copied.stdout))
    args = ["plugin", "install", remote, "--force"]
    if activate:
        args.append("--activate")
    result = _wp(*args)
    if result.returncode != 0:
        raise SystemExit(clean(result.stderr) or clean(result.stdout))
    # CLI runs as root; restore ownership so PHP uploads keep working.
    exec_service(COMPOSE, "cli", "chown", "-R", "www-data:www-data", "/var/www/html/wp-content/plugins")
    if not quiet:
        print(clean(result.stdout).strip())


def reset(quiet: bool = False) -> None:
    if not _snapshot_ready():
        up()
    restore_database(COMPOSE, "db", DB_ROOT_PASSWORD, DB_SNAPSHOT)
    prepared = exec_service(
        COMPOSE,
        "cli",
        "sh",
        "-c",
        "rm -rf /var/www/html/wp-content/plugins /var/www/html/wp-content/uploads",
    )
    if prepared.returncode != 0:
        raise SystemExit(clean(prepared.stderr) or clean(prepared.stdout) or "plugin cleanup failed")
    restored = exec_bytes(
        COMPOSE,
        "cli",
        "tar",
        "-C",
        "/var/www/html/wp-content",
        "-xzf",
        "-",
        input_bytes=PLUGINS_SNAPSHOT.read_bytes(),
    )
    if restored.returncode != 0:
        raise SystemExit(clean(restored.stderr.decode("utf-8", "replace")) or "plugin restore failed")
    exec_service(COMPOSE, "cli", "sh", "-c", "mkdir -p /var/www/html/wp-content/uploads && chown -R www-data:www-data /var/www/html/wp-content/plugins /var/www/html/wp-content/uploads")
    if not quiet:
        print("reset")


def status() -> None:
    for args in (("core", "is-installed"), ("plugin", "list"), ("option", "get", "siteurl")):
        result = _wp(*args)
        print(f"$ wp {' '.join(args)}")
        print(clean(result.stdout or result.stderr))


def validate(
    cve: str,
    vuln: str,
    patched: str | None,
    mode: str,
    url: str,
    proofcms_args: list[str],
    cache_dir: Path | str,
    timeout: int,
    pretty: bool,
    seed_entries: list[Any] | None = None,
    refresh_snapshot: bool = False,
) -> int:
    up(quiet=True)
    if seed_entries:
        _seed(seed_entries)
    if refresh_snapshot:
        # Capture the seeded state so reset() between the vulnerable and
        # patched runs keeps the accounts/content the proof needs.
        snapshot(force=True, quiet=True)
    install(vuln, cache_dir=cache_dir, quiet=True)
    vulnerable = run_proofcms(cve, url, "wordpress", mode, proofcms_args, timeout)

    patched_run = None
    if patched:
        reset(quiet=True)
        install(patched, cache_dir=cache_dir, quiet=True)
        patched_run = run_proofcms(cve, url, "wordpress", mode, proofcms_args, timeout)

    errors = []
    if vulnerable.get("state") != "VULNERABLE" or (patched_run and patched_run.get("state") == "VULNERABLE"):
        errors = php_errors(COMPOSE, "wordpress")
    result = compact(cve, vulnerable, patched_run, errors)
    print(json.dumps(result, indent=2 if pretty else None))
    return 0 if result["verdict"] == "CONFIRMED_WITH_CONTROL" else 2


def _seed(entries: list[Any]) -> None:
    for entry in entries:
        if isinstance(entry, str):
            result = exec_service(COMPOSE, "cli", "sh", "-c", entry)
        elif isinstance(entry, dict):
            service = entry.get("service", "cli")
            command = entry.get("command")
            if not isinstance(command, list):
                raise SystemExit("lab.json seed entries need a command list")
            result = exec_service(COMPOSE, service, *[str(part) for part in command])
        else:
            raise SystemExit("invalid lab.json seed entry")
        if result.returncode != 0:
            raise SystemExit(clean(result.stderr) or clean(result.stdout) or "seed failed")


def run_lab(lab_path: Path, cve: str | None, pretty: bool) -> int:
    lab_dir, config = load_lab(lab_path)
    if config.get("cms", "wordpress") != "wordpress":
        raise SystemExit("wp_lab only runs wordpress lab.json files")
    proof = proof_for(config, cve)
    if "vuln" not in proof:
        raise SystemExit(f"lab.json {lab_dir} has no vuln fixture")
    return validate(
        cve=str(proof.get("_cve") or cve or ""),
        vuln=proof["vuln"],
        patched=proof.get("patched"),
        mode=proof.get("mode", "aggressive"),
        url=proof.get("url", config.get("url", BASE)),
        proofcms_args=list(proof.get("args") or proof.get("proofcms_args") or []),
        cache_dir=proof.get("cache_dir", config.get("cache_dir", DEFAULT_CACHE)),
        timeout=int(proof.get("timeout", config.get("timeout", 120))),
        pretty=pretty,
        seed_entries=list(config.get("seed") or []),
        refresh_snapshot=True,
    )


def down(keep_snapshot: bool = False) -> None:
    compose(COMPOSE, "down", "-v")
    if not keep_snapshot:
        for path in (DB_SNAPSHOT, PLUGINS_SNAPSHOT):
            path.unlink(missing_ok=True)
        try:
            SNAPSHOTS.rmdir()
        except OSError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("up")
    install_parser = sub.add_parser("install")
    install_parser.add_argument("source", help="Plugin URL or local zip path")
    install_parser.add_argument("--no-activate", action="store_true")
    install_parser.add_argument("--cache-dir", default=str(DEFAULT_CACHE))
    sub.add_parser("reset")
    snapshot_parser = sub.add_parser("snapshot")
    snapshot_parser.add_argument("--force", action="store_true")
    sub.add_parser("status")
    down_parser = sub.add_parser("down")
    down_parser.add_argument("--keep-snapshot", action="store_true")

    validate_parser = sub.add_parser("validate")
    validate_parser.add_argument("--cve", required=True)
    validate_parser.add_argument("--vuln", required=True, help="Vulnerable plugin URL or zip")
    validate_parser.add_argument("--patched", help="Patched plugin URL or zip (control)")
    validate_parser.add_argument("--mode", default="aggressive", choices=("safe", "aggressive", "auto"))
    validate_parser.add_argument("--url", default=BASE)
    validate_parser.add_argument("--proofcms-arg", action="append", default=[])
    validate_parser.add_argument("--cache-dir", default=str(DEFAULT_CACHE))
    validate_parser.add_argument("--timeout", type=int, default=120)
    validate_parser.add_argument("--pretty", action="store_true")

    run_parser = sub.add_parser("run")
    run_parser.add_argument("lab", help="Lab directory or lab.json path")
    run_parser.add_argument("--cve", help="Select a proof when lab.json defines several")
    run_parser.add_argument("--pretty", action="store_true")

    args = parser.parse_args()
    if args.command == "up":
        up()
    elif args.command == "install":
        install(args.source, not args.no_activate, args.cache_dir)
    elif args.command == "reset":
        reset()
    elif args.command == "snapshot":
        snapshot(args.force)
    elif args.command == "status":
        status()
    elif args.command == "down":
        down(args.keep_snapshot)
    elif args.command == "validate":
        return validate(
            args.cve,
            args.vuln,
            args.patched,
            args.mode,
            args.url,
            args.proofcms_arg,
            args.cache_dir,
            args.timeout,
            args.pretty,
        )
    elif args.command == "run":
        return run_lab(Path(args.lab), args.cve, args.pretty)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
