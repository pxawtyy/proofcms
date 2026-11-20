"""Shared helpers for the deterministic lab runners.

The runners keep the model out of the shell: they start the stack, install a
fixture, call the ProofCMS CLI with ``--json``, reset from a snapshot, and
return one compact JSON object. The agent only decides the next CVE.
"""

from __future__ import annotations

import json
import re
import secrets
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
PHP_ERROR_RE = re.compile(r"PHP (?:Fatal|Warning|Notice|Parse)|Uncaught", re.IGNORECASE)


def run(
    cmd: list[str],
    cwd: Path = REPO,
    timeout: int | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    options: dict[str, Any] = {
        "cwd": str(cwd),
        "text": True,
        "capture_output": True,
        "timeout": timeout,
    }
    if input_text is None:
        # Never let a prompt (wp-config, credentials) hang the runner.
        options["stdin"] = subprocess.DEVNULL
    else:
        options["input"] = input_text
    return subprocess.run(cmd, check=False, **options)


def _docker(
    compose_file: Path,
    *args: str,
    input_bytes: bytes | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[bytes]:
    options: dict[str, Any] = {
        "capture_output": True,
        "timeout": timeout,
    }
    if input_bytes is None:
        options["stdin"] = subprocess.DEVNULL
    else:
        options["input"] = input_bytes
    return subprocess.run(["docker", "compose", "-f", str(compose_file), *args], check=False, **options)


def compose(compose_file: Path, *args: str, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    return run(["docker", "compose", "-f", str(compose_file), *args], timeout=timeout)


def exec_service(
    compose_file: Path,
    service: str,
    *args: str,
    timeout: int | None = None,
    user: str | None = None,
) -> subprocess.CompletedProcess[str]:
    prefix = ["exec", "-T"]
    if user:
        prefix.extend(["-u", user])
    return run(
        ["docker", "compose", "-f", str(compose_file), *prefix, service, *args],
        timeout=timeout,
    )


def exec_bytes(
    compose_file: Path,
    service: str,
    *args: str,
    input_bytes: bytes | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[bytes]:
    return _docker(
        compose_file,
        "exec",
        "-T",
        service,
        *args,
        input_bytes=input_bytes,
        timeout=timeout,
    )


def clean(text: str) -> str:
    noise = ("Container ", "Network ", "Volume ", " Attaching", " Container")
    return "\n".join(line for line in (text or "").splitlines() if line.strip() and not line.startswith(noise))


def cache_source(source: str, cache_dir: str | Path) -> Path:
    """Return a local file for a URL (downloaded once) or a local path."""
    if source.startswith(("http://", "https://")):
        directory = Path(cache_dir)
        directory.mkdir(parents=True, exist_ok=True)
        name = source.rstrip("/").split("/")[-1].split("?")[0] or "fixture.zip"
        target = directory / name
        if not target.exists():
            urllib.request.urlretrieve(source, target)
        return target
    return Path(source)


def php_errors(compose_file: Path, service: str, tail: int = 120) -> list[str]:
    result = compose(compose_file, "logs", "--tail", str(tail), service)
    lines = [line for line in (result.stdout or "").splitlines() if PHP_ERROR_RE.search(line)]
    return lines[-10:]


def wait_http(url: str, timeout: int = 180, interval: float = 2.0) -> bool:
    """Wait until the URL answers (any HTTP status counts as reachable)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5):
                return True
        except urllib.error.HTTPError:
            return True
        except (urllib.error.URLError, OSError):
            time.sleep(interval)
    return False


def wait_service_file(compose_file: Path, service: str, path: str, timeout: int = 300) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if exec_service(compose_file, service, "test", "-f", path).returncode == 0:
            return True
        time.sleep(3)
    return False


def dump_database(
    compose_file: Path,
    service: str,
    name: str,
    root_password: str,
    target: Path,
) -> None:
    result = _docker(
        compose_file,
        "exec",
        "-T",
        service,
        "mariadb-dump",
        "-uroot",
        f"-p{root_password}",
        "--skip-ssl",
        "--databases",
        name,
    )
    if result.returncode != 0:
        raise SystemExit(clean(result.stderr.decode("utf-8", "replace")) or "database dump failed")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(result.stdout)


def restore_database(compose_file: Path, service: str, root_password: str, source: Path) -> None:
    if not source.exists():
        raise SystemExit(f"snapshot not found: {source} (run the snapshot command first)")
    # Piping a multi-MB dump through ``docker compose exec -T`` stdin is
    # throttled on Docker Desktop (minutes for a Joomla DB). Copy the file
    # into the container and redirect inside it instead.
    remote = f"/tmp/proofcms-restore-{service}.sql"
    copied = compose(compose_file, "cp", str(source), f"{service}:{remote}")
    if copied.returncode != 0:
        raise SystemExit(clean(copied.stderr) or clean(copied.stdout) or "snapshot copy failed")
    password = shlex.quote(f"-p{root_password}")
    result = exec_service(
        compose_file,
        service,
        "sh",
        "-c",
        f"mariadb -uroot {password} --skip-ssl < {shlex.quote(remote)}",
    )
    exec_service(compose_file, service, "rm", "-f", remote)
    if result.returncode != 0:
        raise SystemExit(clean(result.stderr) or clean(result.stdout) or "database restore failed")


def run_proofcms(
    cve: str,
    url: str,
    cms: str,
    mode: str,
    extra_args: list[str] | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    report_path = Path(tempfile.gettempdir()) / f"proofcms-{cve}-{secrets.token_hex(4)}.json"
    cmd = [
        sys.executable,
        "-m",
        "proofcms",
        "-u",
        url,
        "--cms",
        cms,
        "--cve",
        cve,
        "--run-exploit",
        cve,
        "--exploit-mode",
        mode,
        "--i-understand-authorized",
        "--i-understand-lab-only",
        "--no-text-report",
        "--json",
        str(report_path),
        *(extra_args or []),
    ]
    started = time.perf_counter()
    try:
        result = run(cmd, timeout=timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        result = subprocess.CompletedProcess(cmd, 124, "", f"timed out after {timeout}s")
        timed_out = True
    duration = round(time.perf_counter() - started, 3)
    finding: dict[str, Any] = {}
    if report_path.exists():
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            wanted = cve.upper()
            for target in report.get("targets", []):
                for item in target.get("results", []):
                    if str(item.get("cve", "")).upper() == wanted:
                        finding = item
        except (json.JSONDecodeError, OSError):
            finding = {}
        finally:
            report_path.unlink(missing_ok=True)
    state = finding.get("status")
    if timed_out:
        state = "TIMEOUT"
    elif not state:
        state = "ERROR" if result.returncode not in (0, 1, 2) else "UNKNOWN"
    return {
        "state": state,
        "confidence": finding.get("confidence"),
        "exit_code": result.returncode,
        "duration_s": duration,
        "detail": str(finding.get("detail", ""))[:400],
        "stderr_tail": clean(result.stderr)[-400:],
    }


def verdict(vulnerable: dict[str, Any], patched: dict[str, Any] | None) -> str:
    state = vulnerable.get("state")
    if state == "VULNERABLE_UPLOAD_ONLY":
        return "UPLOAD_ONLY"
    if state != "VULNERABLE":
        return "NOT_REPRODUCED"
    if patched is None:
        return "VULNERABLE"
    if patched.get("state") == "VULNERABLE":
        return "VULNERABLE_NO_CONTROL"
    return "CONFIRMED_WITH_CONTROL"


def compact(
    cve: str,
    vulnerable: dict[str, Any],
    patched: dict[str, Any] | None,
    php_errors_tail: list[str] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "cve": cve,
        "verdict": verdict(vulnerable, patched),
        "vulnerable": vulnerable,
    }
    if patched is not None:
        result["patched"] = patched
    result["php_errors_tail"] = php_errors_tail or []
    return result


def load_lab(path: str | Path) -> tuple[Path, dict[str, Any]]:
    """Load ``lab.json`` from a file or a lab directory."""
    candidate = Path(path)
    if candidate.is_dir():
        candidate = candidate / "lab.json"
    if not candidate.exists():
        raise SystemExit(f"lab.json not found: {candidate}")
    try:
        config = json.loads(candidate.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid lab.json: {exc}") from exc
    if not isinstance(config, dict):
        raise SystemExit("invalid lab.json: top level must be an object")
    return candidate.parent.resolve(), config


def proof_for(config: dict[str, Any], cve: str | None) -> dict[str, Any]:
    """Merge the shared lab settings with the selected CVE's proof block."""
    proofs = config.get("proofs") or {}
    if not isinstance(proofs, dict):
        raise SystemExit("invalid lab.json: proofs must be an object")
    if not proofs:
        if not cve:
            raise SystemExit("lab.json has no proofs block; pass --cve")
        return {**config, "_cve": cve}
    lookup = {str(key).upper(): (key, value) for key, value in proofs.items()}
    if cve and cve.upper() in lookup:
        key, value = lookup[cve.upper()]
        return {**config, **value, "_cve": key}
    if not cve and len(proofs) == 1:
        key, value = next(iter(lookup.values()))
        return {**config, **value, "_cve": key}
    available = ", ".join(sorted(proofs))
    raise SystemExit(f"select one proof with --cve ({available})")
