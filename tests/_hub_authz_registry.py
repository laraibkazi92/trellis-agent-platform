# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Hermetic authz registry stand-in for hub tool-call tests.

Every hub tool call now asks the direct-call gate, and ``core.tool_authz`` imports
``get_identity_manager`` from ``core.auth`` lazily -- patching the hub's own binding is
not enough. Without this stub the first call in each cache window would attempt a real
etcd read (with the ``@retry_etcd`` backoff on failure) and could write synthetic
entries into the live deny ring.
"""

from core import auth, tool_authz


class FakeAuthzRegistry:
    """Policy document, every rollout mode, the deny ring and agent configs."""

    def __init__(
        self,
        *,
        policy=None,
        mode="off",
        bound_mode="off",
        hub_mode="off",
        groups=None,
        agent_configs=None,
    ):
        self.policy = {} if policy is None else policy
        self.mode = mode
        self.bound_mode = bound_mode
        self.hub_mode = hub_mode
        self.groups = {} if groups is None else groups
        self.agent_configs = {} if agent_configs is None else agent_configs
        self.denies = []
        self.policy_reads = 0

    def get_tool_policies(self):
        self.policy_reads += 1
        return self.policy

    def get_tool_authz_mode(self):
        return self.mode

    def get_bound_tools_mode(self):
        return self.bound_mode

    def get_hub_call_mode(self):
        return self.hub_mode

    def get_principal_groups(self):
        return self.groups

    def get_agent_config(self, name):
        return self.agent_configs.get(name)

    def append_tool_authz_deny(self, entry, cap: int = 200):
        self.denies.insert(0, entry)
        del self.denies[cap:]

    def get_tool_authz_denies(self):
        return list(self.denies)

    def clear_tool_authz_denies(self):
        self.denies.clear()


def install(monkeypatch, **kwargs) -> FakeAuthzRegistry:
    """Point the policy engine at a fake registry and drop the cached snapshot."""
    fake = FakeAuthzRegistry(**kwargs)
    monkeypatch.setattr(auth, "get_identity_manager", lambda: fake)
    tool_authz.reset_cache()
    return fake
