"""Fast WordPress fixture runner for lab validation.

Reuses one pinned WordPress + MariaDB stack and installs plugin versions with
WP-CLI instead of building a new compose file per CVE. Typical loop:

    python tools/wp_lab.py up
    python tools/wp_lab.py install https://downloads.wordpress.org/plugin/forminator.1.35.1.zip
    python -m proofcms -u http://127.0.0.1:9212 --cve CVE-2024-10402 ...
    python tools/wp_lab.py reset
    python tools/wp_lab.py install https://downloads.wordpress.org/plugin/forminator.1.36.0.zip
    python tools/wp_lab.py down
"""

from __future__ import annotations

import argparse
import subprocess
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
COMPOSE = REPO / "labs" / "_wp-base" / "compose.yml"
BASE = "http://127.0.0.1:9212"
ADMIN = "admin"
PASSWORD = "proofcms-lab-password"
EMAIL = "lab@example.test"
DB_NAME = "wordpress"
DB_ROOT_PASSWORD = "proofcms"


def _run(cmd: list[str], check: bool = False) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(cmd, cwd=REPO, text=True, capture_output=True, check=False)
    if check and result.returncode != 0:
        raise SystemExit(_clean(result.stderr) or _clean(result.stdout) or f"command failed: {cmd}")
    return result


def _compose(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return _run(["docker", "compose", "-f", str(COMPOSE), *args], check=check)


def _wp(*args: str, volumes: list[str] | None = None, check: bool = False) -> subprocess.CompletedProcess[str]:
    cmd = ["docker", "compose", "-f", str(COMPOSE), "--profile", "tools", "run", "--rm"]
    for volume in volumes or []:
        cmd.extend(["-v", volume])
    cmd.extend(["cli", *args, "--allow-root"])
    return _run(cmd, check=check)


def _clean(text: str) -> str:
    noise = ("Container ", "Network ", "Volume ", " Attaching", " Container")
    return "\n".join(line for line in text.splitlines() if line.strip() and not line.startswith(noise))


def _wait_installed(timeout: int = 90) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _wp("core", "is-installed").returncode == 0:
            return True
        time.sleep(2)
    return False


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
        raise SystemExit(_clean(result.stderr) or _clean(result.stdout))
    _wp("rewrite", "structure", "/%postname%/", "--hard")
    _wp("rewrite", "flush", "--hard")


def up() -> None:
    _compose("up", "-d", "--wait")
    if not _wait_installed():
        _install_core()
    print(BASE)


def install(source: str, activate: bool = True) -> None:
    path = Path(source)
    volumes: list[str] = []
    if path.exists():
        volumes = [f"{path.resolve().parent}:/fixtures:ro"]
        source = f"/fixtures/{path.name}"
    args = ["plugin", "install", source, "--force"]
    if activate:
        args.append("--activate")
    result = _wp(*args, volumes=volumes)
    if result.returncode != 0:
        raise SystemExit(_clean(result.stderr) or _clean(result.stdout))
    print(result.stdout.strip())


def _drop_database() -> None:
    """Drop and recreate the WordPress database.

    ``wp db reset`` shells out to the MariaDB client, which negotiates TLS by
    default in this image and fails against the plaintext lab server. Running
    the client with ``--skip-ssl`` keeps the reset deterministic.
    """
    result = _run([
        "docker", "compose", "-f", str(COMPOSE), "exec", "-T", "db",
        "mariadb", "-uroot", f"-p{DB_ROOT_PASSWORD}", "--skip-ssl",
        "-e", f"DROP DATABASE IF EXISTS {DB_NAME}; CREATE DATABASE {DB_NAME};",
    ])
    if result.returncode != 0:
        raise SystemExit(_clean(result.stderr) or _clean(result.stdout))


def reset() -> None:
    _wp("plugin", "deactivate", "--all")
    _wp("plugin", "delete", "--all")
    _drop_database()
    _install_core()
    print("reset")


def status() -> None:
    for args in (("core", "is-installed"), ("plugin", "list"), ("option", "get", "siteurl")):
        result = _wp(*args)
        print(f"$ wp {' '.join(args)}")
        print(_clean(result.stdout or result.stderr))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("up")
    install_parser = sub.add_parser("install")
    install_parser.add_argument("source", help="Plugin URL or local zip path")
    install_parser.add_argument("--no-activate", action="store_true")
    sub.add_parser("reset")
    sub.add_parser("status")
    sub.add_parser("down")
    args = parser.parse_args()
    if args.command == "up":
        up()
    elif args.command == "install":
        install(args.source, not args.no_activate)
    elif args.command == "reset":
        reset()
    elif args.command == "status":
        status()
    elif args.command == "down":
        _compose("down", "-v", check=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
