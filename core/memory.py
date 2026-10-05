# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""
Agent memory backed by Hindsight (https://github.com/vectorize-io/hindsight).

This is a framework-level concern. Business logic only opts in via `agent_memory: true`
in an agent's config.yaml, and an admin master switch (the `agent_memory_enabled`
framework feature flag, toggled from the admin dashboard) gates the whole feature.

Scope: memory is per-agent. By default the Hindsight "bank" key is the agent name, so
an agent accumulates institutional knowledge across every user that talks to it. Admins
can flip the `agent_memory_isolated_per_user` framework flag to key banks as
"{agent_name}:{user_id}" instead, giving each user a private memory (runs without a
user identity degrade to the shared agent bank). Existing shared banks are not migrated.

Every operation is fail-open: a Hindsight outage, a missing client library, or an API
mismatch degrades to "no memory" and never breaks an agent run.
"""
import os
import asyncio
import time
from typing import Any, Optional, Union

# Framework feature flag key (etcd: /config/framework/agent_memory_enabled)
MEMORY_FLAG_KEY = "agent_memory_enabled"

# Framework feature flag key (etcd: /config/framework/agent_memory_isolated_per_user)
MEMORY_ISOLATION_FLAG_KEY = "agent_memory_isolated_per_user"

# The global flag is cached briefly so the recall instruction does not hit etcd on every
# run. Toggling the flag from the admin dashboard takes effect within this many seconds.
_FLAG_TTL_SECONDS = 20.0

# How many recalled facts to inject into context.
_RECALL_LIMIT = 5


class MemoryManager:
    """Thin async wrapper over the (synchronous) Hindsight client."""

    def __init__(self, identity_mgr: Any, base_url: Optional[str] = None):
        self._identity_mgr = identity_mgr
        self._base_url = base_url or os.getenv("HINDSIGHT_URL", "http://hindsight:8888")
        self._client: Any = None
        self._flag_cache: Optional[bool] = None
        self._flag_ts: float = 0.0
        self._isolation_flag_cache: Optional[bool] = None
        self._isolation_flag_ts: float = 0.0

    # --- Client management -------------------------------------------------

    def _get_client(self) -> Any:
        if self._client is None:
            # Imported lazily so the framework still boots if the dependency is absent.
            from hindsight_client import Hindsight
            self._client = Hindsight(base_url=self._base_url)
        return self._client

    # --- Feature gating ----------------------------------------------------

    def is_globally_enabled(self) -> bool:
        """True if the admin master switch is on. Cached for a short TTL."""
        now = time.monotonic()
        if self._flag_cache is None or (now - self._flag_ts) > _FLAG_TTL_SECONDS:
            try:
                self._flag_cache = bool(self._identity_mgr.get_config(MEMORY_FLAG_KEY, False))
            except Exception as e:
                print(f"[memory] failed reading feature flag, defaulting off: {e}")
                self._flag_cache = False
            self._flag_ts = now
        return self._flag_cache

    def is_isolated_per_user(self) -> bool:
        """True if per-user memory isolation is on. Cached for a short TTL."""
        now = time.monotonic()
        if self._isolation_flag_cache is None or (now - self._isolation_flag_ts) > _FLAG_TTL_SECONDS:
            try:
                self._isolation_flag_cache = bool(self._identity_mgr.get_config(MEMORY_ISOLATION_FLAG_KEY, False))
            except Exception as e:
                print(f"[memory] failed reading isolation flag, defaulting off: {e}")
                self._isolation_flag_cache = False
            self._isolation_flag_ts = now
        return self._isolation_flag_cache

    def bank_for(self, agent_name: str, user_id: Optional[str]) -> str:
        """Resolve the Hindsight bank key for a run. With per-user isolation on and a
        known user, memories live in "{agent_name}:{user_id}"; otherwise the bank is
        the shared agent name (runs without a user identity degrade to shared)."""
        if self.is_isolated_per_user() and user_id:
            return f"{agent_name}:{user_id}"
        return agent_name

    def active_for(self, agent_config: Union[dict, Any]) -> bool:
        """Memory is active for an agent only if the master switch is on AND the agent
        opted in via `agent_memory: true` in its config."""
        if not self.is_globally_enabled():
            return False
        if isinstance(agent_config, dict):
            return bool(agent_config.get("agent_memory", False))
        return bool(getattr(agent_config, "agent_memory", False))

    # --- Recall ------------------------------------------------------------

    async def recall(self, bank: str, query: str, limit: int = _RECALL_LIMIT) -> str:
        """Return a formatted memory block for the query, or "" if none / on any error."""
        if not query or not query.strip():
            return ""
        try:
            client = self._get_client()
            try:
                resp = await client.arecall(bank_id=bank, query=query, top_k=limit)
            except TypeError:
                resp = await client.arecall(bank_id=bank, query=query)

            # Response shape: object with `.results` (list of RecallResult), or a bare list.
            results = getattr(resp, "results", None)
            if results is None and isinstance(resp, (list, tuple)):
                results = resp
            if not results:
                return ""

            lines = []
            for r in results[:limit]:
                text = getattr(r, "text", None)
                if text is None and isinstance(r, dict):
                    text = r.get("text")
                if text:
                    lines.append(f"- {text}")

            if not lines:
                return ""
            return "## Relevant context from past interactions\n" + "\n".join(lines)
        except Exception as e:
            print(f"[memory] recall failed for bank='{bank}': {e}")
            return ""

    # --- Retain ------------------------------------------------------------

    async def retain(self, bank: str, user_msg: str, agent_output: str) -> None:
        """Store one user/agent exchange under the agent's bank. Never raises."""
        if not user_msg or not agent_output:
            return
        try:
            client = self._get_client()
            content = f"User asked: {user_msg}\nAgent responded: {agent_output}"
            await client.aretain(bank_id=bank, content=content, context="conversation")
        except Exception as e:
            print(f"[memory] retain failed for bank='{bank}': {e}")


_memory_mgr: Optional[MemoryManager] = None


def get_memory_manager() -> MemoryManager:
    global _memory_mgr
    if _memory_mgr is None:
        # Reuse the shared IdentityManager singleton. Imported lazily to avoid a circular
        # import with agent_factory at module load time.
        from core.agent_factory import get_identity_manager
        _memory_mgr = MemoryManager(get_identity_manager())
    return _memory_mgr
