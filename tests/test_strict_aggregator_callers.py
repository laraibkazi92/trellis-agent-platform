"""Regression tests: write-path callers of the discovery aggregators must pass
``strict=True`` so a failed tool/MCP config fetch raises instead of silently
dropping requirements (which would let a save path accept/skip the wrong keys).

Approach per call site:
  - core/routers/marketplace.py  -> behavioral (drive configure_agent_secrets with
    patched aggregators that record kwargs)
  - core/routers/workflows.py    -> behavioral (drive configure_background_agent_secrets)
  - core/tasks.py                -> AST (the call sits deep inside the subprocess
    launch path of the workflow runner; driving it needs a real entrypoint file)
"""
import ast
import asyncio
from pathlib import Path
from types import SimpleNamespace

from core.routers import marketplace, workflows

AGGREGATORS = (
    "get_agent_required_secrets",
    "get_agent_required_variables",
    "get_agent_secret_groups",
)


class _FakeMgr:
    def get_agent_config(self, name):
        return {"name": name, "type": "user_agent"}

    def get_identity_config(self, identity, kind):
        return {}

    def save_identity_config(self, identity, kind, data):
        pass


def _install_recorders(monkeypatch, module):
    calls = {}

    def make(name, ret):
        async def fake(config, **kwargs):
            calls[name] = kwargs
            return ret
        return fake

    monkeypatch.setattr(module, "get_agent_required_secrets", make("get_agent_required_secrets", []))
    monkeypatch.setattr(module, "get_agent_required_variables", make("get_agent_required_variables", []))
    monkeypatch.setattr(module, "get_agent_secret_groups", make("get_agent_secret_groups", []))
    monkeypatch.setattr(module, "identity_mgr", _FakeMgr())
    return calls


class _FakeRequest:
    def __init__(self):
        self.session = {"user": {"sub": "admin-1", "email": "a@example.com"}}

    async def form(self):
        return {}


def test_marketplace_configure_passes_strict_true(monkeypatch):
    calls = _install_recorders(monkeypatch, marketplace)
    asyncio.run(marketplace.configure_agent_secrets(_FakeRequest(), "some-agent"))
    assert set(calls) == set(AGGREGATORS)
    for name, kwargs in calls.items():
        assert kwargs.get("strict") is True, f"marketplace dropped strict=True on {name}"


def test_workflows_configure_passes_strict_true(monkeypatch):
    calls = _install_recorders(monkeypatch, workflows)

    async def fake_user(request):
        return {"sub": "admin-1"}

    monkeypatch.setattr(workflows, "get_current_user", fake_user)
    monkeypatch.setattr(workflows, "is_admin", lambda request: True)
    asyncio.run(workflows.configure_background_agent_secrets(_FakeRequest(), "some-workflow"))
    assert set(calls) == set(AGGREGATORS)
    for name, kwargs in calls.items():
        assert kwargs.get("strict") is True, f"workflows dropped strict=True on {name}"


def test_tasks_aggregator_calls_pass_strict_true():
    """AST check: every aggregator call in core/tasks.py has a strict=True keyword."""
    src = (Path(__file__).resolve().parent.parent / "core" / "tasks.py").read_text()
    tree = ast.parse(src)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", None)
            if name in AGGREGATORS or name == "get_agent_optional_secrets":
                found.append(name)
                kw = {k.arg: k.value for k in node.keywords}
                assert "strict" in kw and isinstance(kw["strict"], ast.Constant) \
                    and kw["strict"].value is True, f"core/tasks.py: {name} call missing strict=True"
    assert "get_agent_required_secrets" in found and "get_agent_required_variables" in found
