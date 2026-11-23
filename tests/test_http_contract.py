from __future__ import annotations

import ast
from pathlib import Path

from proofcms.core.http import HttpClient, application_base_url, probe_target_baseline

PACKAGE_ROOT = Path(__file__).resolve().parent.parent / "proofcms"


def _is_relative_call(node: ast.Call) -> bool:
    return bool(
        node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
        and node.args[0].value.startswith("/")
    )


def _client_has_base(call: ast.Call) -> bool:
    return any(keyword.arg == "base_url" for keyword in call.keywords) or bool(call.args)


def find_relative_http_violations(source: str) -> list[str]:
    """Return client variables that request a relative path without a base URL."""
    tree = ast.parse(source)
    baseless: dict[str, int] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        call = node.value
        if not (isinstance(call.func, ast.Name) and call.func.id == "HttpClient"):
            continue
        if not _client_has_base(call) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            baseless[node.targets[0].id] = call.lineno

    violations: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in {"get", "request", "post"} or not _is_relative_call(node):
            continue
        owner = node.func.value
        if isinstance(owner, ast.Name) and owner.id in baseless:
            violations.append(f"line {node.lineno}: {owner.id} requests a relative path")
        elif (
            isinstance(owner, ast.Call)
            and isinstance(owner.func, ast.Name)
            and owner.func.id == "HttpClient"
            and not _client_has_base(owner)
        ):
            violations.append(f"line {node.lineno}: chained HttpClient requests a relative path")
    return violations


def test_detects_baseless_relative_client():
    source = 'from x import HttpClient\nclient = HttpClient(timeout=1)\nclient.get("/")\n'
    assert find_relative_http_violations(source)


def test_detects_chained_baseless_relative_client():
    source = 'from x import HttpClient\nHttpClient(timeout=1).get("/login")\n'
    assert find_relative_http_violations(source)


def test_allows_explicit_base_url():
    source = 'from x import HttpClient\nclient = HttpClient(base_url="https://target.example", timeout=1)\nclient.get("/")\n'
    assert not find_relative_http_violations(source)


def test_allows_absolute_urls_without_base():
    source = 'from x import HttpClient\nclient = HttpClient(timeout=1)\nclient.get("https://target.example/")\n'
    assert not find_relative_http_violations(source)


def test_repository_has_no_baseless_relative_clients():
    failures: list[str] = []
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        violations = find_relative_http_violations(path.read_text(encoding="utf-8"))
        if violations:
            failures.append(f"{path.relative_to(PACKAGE_ROOT)}: {violations[0]}")
    assert not failures, "\n".join(failures)


def test_relative_url_without_base_is_an_explicit_error():
    response = HttpClient(timeout=1).get("/")
    assert response.get("status") == 0
    assert response.get("error")


def test_application_base_strips_a_document_segment():
    assert application_base_url("https://host/portal/app.aspx") == "https://host/portal"
    assert application_base_url("https://host/app.aspx") == "https://host"
    assert application_base_url("https://host/joomla/index.php") == "https://host/joomla"
    assert application_base_url("https://host/portal") == "https://host/portal"
    assert application_base_url("https://host") == "https://host"


def test_document_base_is_not_resolved_as_a_directory():
    client = HttpClient(base_url="https://host/portal/app.aspx", timeout=1)
    assert client._resolve_url("/") == "https://host/portal/"
    assert client._resolve_url("applogin.aspx") == "https://host/portal/applogin.aspx"
    assert client._resolve_url("/login.aspx") == "https://host/portal/login.aspx"
    assert client._resolve_url("/app.aspx") == "https://host/portal/app.aspx"


def test_baseline_does_not_append_slash_to_a_document(monkeypatch):
    calls: list[str] = []

    def fake_fetch(url: str, **kwargs):
        calls.append(url)
        return {"status": 200, "body": "", "final_url": url}

    monkeypatch.setattr("proofcms.core.http.fetch_url", fake_fetch)
    probe_target_baseline("https://host/portal/app.aspx", timeout=1)
    assert calls[0] == "https://host/portal/"
    assert calls[1].startswith("https://host/portal/_jvh_probe_")
    assert all("app.aspx/" not in url for url in calls)
