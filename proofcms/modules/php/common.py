from __future__ import annotations

import secrets
from collections.abc import Callable
from typing import Any

from ...core.http import HttpClient
from ...core.models import Confidence, Finding, Status


def runtime_finding(
    *,
    cve: str,
    name: str,
    rule: str,
    php_runtime: dict[str, Any] | None,
    classify: Callable[[str | None], str],
    action: str,
    exploit_available: bool,
) -> Finding:
    runtime = php_runtime or {}
    detected = bool(runtime.get("detected"))
    version = runtime.get("version")
    if not detected:
        return Finding(
            cve,
            name,
            Status.NOT_DETECTED,
            Confidence.LOW,
            "PHP runtime",
            None,
            rule,
            exploit_available,
            detail="PHP was not fingerprinted from public HTTP responses.",
            action=action,
        )
    status = classify(version)
    if status == Status.LIKELY_VULNERABLE:
        detail = f"Detected PHP {version}; this version is affected when the required web-server/SAPI configuration is present."
        confidence = Confidence.MEDIUM
    elif status == Status.PATCHED:
        detail = f"Detected PHP {version}, which includes the branch-specific security fix."
        confidence = Confidence.HIGH
    else:
        detail = "PHP was detected, but its version could not be determined from public HTTP responses."
        confidence = Confidence.LOW
    server = runtime.get("server")
    if server:
        detail += f" Server header: {server}."
    return Finding(
        cve, name, status, confidence, "PHP runtime", version, rule, exploit_available, detail=detail, action=action
    )


def harmless_cgi_marker_probe(
    target_url: str,
    runtime: dict[str, Any],
    encoded_query: str,
    timeout: int,
    proxy: str | None,
) -> tuple[bool, str, int]:
    marker = f"PROOFCMS_{secrets.token_hex(10)}"
    path = str(runtime.get("entrypoint") or "/index.php")
    if not path.startswith("/"):
        path = "/index.php"
    proof_url = f"{target_url.rstrip('/')}{path}?{encoded_query}"
    body = f'<?php echo "{marker}"; ?>'.encode()
    response = HttpClient(timeout=timeout, proxy=proxy).post(
        proof_url,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    return marker in str(response.get("body", "")), proof_url, int(response.get("status", 0))
