# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for cycle-4 Phase 6 (I8) — IdentityManager singleton consolidation.

Before: six core modules each constructed their own module-level `IdentityManager`
(up to seven etcd client connections per process), and `core/agent_factory.py` owned a
separate lazy singleton. After: `core/auth.get_identity_manager()` is the single lazy
singleton, and every module binds its `identity_mgr` alias to that same object.

The per-module attribute stays in place as a test seam, so patching one module's
`identity_mgr` must still scope to that module and not rebind the others.
"""

from core.auth import get_identity_manager


def test_get_identity_manager_returns_shared_instance():
    assert get_identity_manager() is get_identity_manager()


def test_modules_bind_shared_singleton():
    from core import auth, discovery, gateway, tool_search, hub, agent_search, rules_engine
    from core import agent_factory, dependencies, host
    from core.background import webhooks
    from core.routers import admin

    assert agent_factory.get_identity_manager is auth.get_identity_manager

    assert (
        discovery.identity_mgr
        is gateway.identity_mgr
        is tool_search.identity_mgr
        is hub.identity_mgr
        is agent_search.identity_mgr
        is rules_engine.identity_mgr
        is dependencies.identity_mgr
        is admin.identity_mgr
        is host.identity_mgr
        is webhooks.identity_mgr
        is agent_factory.get_identity_manager()
    )


def test_module_attribute_patch_still_scopes(monkeypatch):
    from core import discovery, tool_search

    sentinel = object()
    monkeypatch.setattr(discovery, "identity_mgr", sentinel)

    assert tool_search.identity_mgr is not sentinel
    assert tool_search.identity_mgr is get_identity_manager()
