from __future__ import annotations

import re
from html import unescape
from typing import Any

from ...core.http import HttpClient, normalize_url
from ...core.probes import extract_csrf_from_html, rand_str

REGISTRATION_PATH = "/index.php?option=com_users&view=registration"
REGISTER_TASK = "registration.register"


def _collision_markers(body: str) -> list[str]:
    """Return durable username/e-mail uniqueness signals from Joomla translations."""
    patterns = {
        "username_exists": (
            r"username.{0,100}(?:already|in use|invalid)",
            r"nome de usu[aá]rio.{0,120}(?:inv[aá]lido|uso)",
            r"nombre de usuario.{0,120}(?:inv[aá]lido|uso)",
        ),
        "email_exists": (
            r"e-?mail.{0,120}(?:already|in use|invalid)",
            r"endere[cç]o de e-?mail.{0,120}(?:uso|inv[aá]lido)",
            r"correo electr[oó]nico.{0,120}(?:uso|inv[aá]lido)",
        ),
    }
    plain = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", unescape(body))).lower()
    return [name for name, variants in patterns.items() if any(re.search(pattern, plain) for pattern in variants)]


def _registration_fields(
    *, token: str, suffix: str, username: str, password: str, email: str, group: int | None
) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "user[name]": f"ProofCMS {suffix}",
        "user[username]": username,
        "user[password1]": password,
        "user[password2]": password,
        "user[email1]": email,
        "user[email2]": email,
        "option": "com_users",
        "task": REGISTER_TASK,
        token: "1",
    }
    if group is not None:
        fields["groups[]"] = str(group)
    return fields


def _fresh_token(client: HttpClient, endpoint: str, timeout: int) -> tuple[str | None, dict[str, Any]]:
    last_page: dict[str, Any] = {}
    for path in (endpoint, "/", "/index.php?option=com_users&view=login"):
        page = client.get(path, timeout=timeout)
        last_page = page
        token = extract_csrf_from_html(page.get("body", ""))
        if token:
            return token, page
    return None, last_page


def submit_registration(
    target_url: str,
    *,
    group: int | None,
    timeout: int = 12,
    proxy: str | None = None,
) -> dict[str, Any]:
    """Create one disposable candidate and verify persistence with a collision oracle."""
    base = normalize_url(target_url)
    client = HttpClient(base_url=base, timeout=timeout, proxy=proxy)
    endpoint = f"{base}{REGISTRATION_PATH}"
    token, form = _fresh_token(client, endpoint, timeout)
    if not token:
        return {
            "sent": False,
            "reason": "No session-bound CSRF token was found on the registration page.",
            "form_status": form.get("status", 0),
            "proof_url": endpoint,
        }

    suffix = rand_str(10)
    username = f"proofcms_{suffix}"
    password = f"Pc!{rand_str(14)}"
    email = f"{username}@example.invalid"
    first = client.post(
        endpoint,
        fields=_registration_fields(
            token=token,
            suffix=suffix,
            username=username,
            password=password,
            email=email,
            group=group,
        ),
        timeout=timeout,
    )

    # Redirects and login response differences do not prove persistence. A
    # repeat submission must hit Joomla's username and e-mail uniqueness checks.
    second_token, second_form = _fresh_token(client, endpoint, timeout)
    second: dict[str, Any] | None = None
    markers: list[str] = []
    if second_token:
        second = client.post(
            endpoint,
            fields=_registration_fields(
                token=second_token,
                suffix=suffix,
                username=username,
                password=password,
                email=email,
                group=group,
            ),
            timeout=timeout,
        )
        markers = _collision_markers(second.get("body", ""))

    account_created = "username_exists" in markers and "email_exists" in markers
    return {
        "sent": True,
        "accepted": account_created,
        "account_created": account_created,
        "status": first.get("status", 0),
        "redirected": first.get("redirected", False),
        "final_url": first.get("final_url", ""),
        "username": username,
        "password": password,
        "email": email,
        "group": group,
        "proof_url": endpoint,
        "registration_task": REGISTER_TASK,
        "group_field": "groups[]" if group is not None else None,
        "collision_checked": second is not None,
        "collision_markers": markers,
        "collision_status": second.get("status", 0) if second else second_form.get("status", 0),
    }
