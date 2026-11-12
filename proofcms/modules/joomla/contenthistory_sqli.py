"""Shared read-only probe for the Joomla com_contenthistory SQL injection family.

Joomla security advisory 20151001 (CVE-2015-7297 / CVE-2015-7857 / CVE-2015-7858)
covers one root cause: the unauthenticated front-end entry point to
com_contenthistory feeds the request's ``list[select]`` value straight into the
``SELECT`` clause of the history query. The modules for each CVE use a
different harmless payload against the same sink so the differential stays
read-only: a control value is accepted, an invalid SQL fragment produces a
database error, and nothing is written.
"""

from __future__ import annotations

import html
import re
import urllib.parse
from typing import Any

from ...core.http import HttpClient, form_encode, normalize_url

SQL_ERROR = re.compile(
    r"(sql syntax|database error|mysqli?_[a-z_]+\(|you have an error in your sql"
    r"|unknown column|doesn't exist|does not exist|jdatabaseexception|xpath syntax error)",
    re.IGNORECASE,
)

BASE_PARAMS = {
    "option": "com_contenthistory",
    "view": "history",
    "item_id": "1",
    "type_id": "1",
    "list[ordering]": "editor",
}


def _send(
    client: HttpClient,
    base: str,
    select_value: str,
    *,
    method: str,
    timeout: int,
) -> dict[str, Any]:
    params = {**BASE_PARAMS, "list[select]": select_value}
    if method.upper() == "POST":
        return client.request(
            f"{base}/index.php",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=form_encode(params),
            timeout=timeout,
            follow_redirects=False,
        )
    url = f"{base}/index.php?{urllib.parse.urlencode(params)}"
    return client.get(url, timeout=timeout)


def run_differential(
    target_url: str,
    payload: str,
    *,
    method: str = "GET",
    signature: str | None = None,
    timeout: int = 12,
    proxy: str | None = None,
) -> dict[str, Any]:
    """Run the control/probe pair and return raw evidence plus a verdict.

    ``signature`` is an extra literal that must appear in the probe response
    (for example the table name used in the injected subquery). It keeps the
    verdict tied to the specific payload rather than any generic error page.
    """
    base = normalize_url(target_url)
    client = HttpClient(timeout=timeout, proxy=proxy)
    control = _send(client, base, "1", method=method, timeout=timeout)
    probe = _send(client, base, payload, method=method, timeout=timeout)

    control_body = control.get("body", "") or ""
    probe_body = probe.get("body", "") or ""
    control_text = html.unescape(control_body)
    probe_text = html.unescape(probe_body)
    control_error = bool(SQL_ERROR.search(control_text))
    probe_error = bool(SQL_ERROR.search(probe_text))
    signature_hit = signature is None or signature in probe_text
    body_diff = probe.get("body_hash") != control.get("body_hash")
    confirmed = probe_error and not control_error and signature_hit and body_diff

    evidence: dict[str, Any] = {
        "method": method.upper(),
        "control_status": control.get("status"),
        "probe_status": probe.get("status"),
        "control_sql_error": control_error,
        "probe_sql_error": probe_error,
        "signature_hit": signature_hit,
        "body_diff": body_diff,
    }
    return {
        "confirmed": confirmed,
        "evidence": evidence,
        "proof_url": f"{base}/index.php?option=com_contenthistory&view=history&list%5Bselect%5D="
        + urllib.parse.quote(payload, safe=""),
        "control": control,
        "probe": probe,
    }
