from __future__ import annotations

from typing import Any

from ...core.http import HttpClient, normalize_url
from ...core.probes import extract_csrf_from_html, rand_str

REGISTRATION_PATH = "/index.php?option=com_users&view=registration"
REGISTER_PATH = "/index.php?option=com_users&task=user.register"


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
    }
