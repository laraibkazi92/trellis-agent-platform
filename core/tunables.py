# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Operational tunables: env-var defaults overridable at runtime from the Admin Dashboard.

Each tunable resolves as ``etcd override (Admin Dashboard -> Limits & Tuning) > env var >
built-in default``, cast to its declared type. This mirrors the branding
(core/dependencies.py) and Rules Engine (core/rules_engine.py) override patterns:
overrides live at ``/config/framework/tunable_<name>``, the env vars are only the shipped
defaults, and the effective value is served from a short-lived in-process cache so a hot
path never blocks on etcd.

The cache is refreshed out of band in a thread-pool worker using a raw, non-retrying etcd
``get`` (same rationale as ``IdentityManager.get_branding``): a blipping etcd must fail fast
and keep serving the last-known values instead of triggering the ~20s ``@retry_etcd`` storm
that ``IdentityManager.get_config`` would on a live request path.
"""
import asyncio
import logging
import os
import time
from typing import Any, NamedTuple, Optional

from core.auth import get_identity_manager

logger = logging.getLogger(__name__)


class Tunable(NamedTuple):
    env_var: str
    default: Any
    type: type


# name -> (env var, built-in default, type). An unset env var + no override must reproduce
# the pre-migration behavior exactly; these defaults are the historical hard-coded values.
TUNABLES: dict[str, Tunable] = {
    "max_run_output_chars": Tunable("MAX_RUN_OUTPUT_CHARS", 32768, int),
    "max_run_error_chars": Tunable("MAX_RUN_ERROR_CHARS", 4096, int),
    "tool_execution_timeout": Tunable("TOOL_EXECUTION_TIMEOUT", 300.0, float),
    # One `background_script` run is ONE container (v0.7.1 Phase 6): this is both the
    # deadline the runner kills it at and the worker's own wait, so it has to outlast
    # a real pipeline -- a tool's 300 s default would cut most of them off.
    "workflow_run_timeout": Tunable("WORKFLOW_RUN_TIMEOUT", 3600.0, float),
    # A saturated runner pool answers 429 (`capacity_exhausted`), which for a workflow
    # is a wait, not a failure: the worker retries within this window and charges the
    # wait against `workflow_run_timeout` above (v0.7.2 R4). 0 disables the wait.
    "workflow_slot_wait": Tunable("WORKFLOW_SLOT_WAIT_S", 300.0, float),
    "tool_search_limit": Tunable("TOOL_SEARCH_LIMIT", 8, int),
    "agent_search_limit": Tunable("AGENT_SEARCH_LIMIT", 8, int),
    "health_failure_threshold": Tunable("HEALTH_FAILURE_THRESHOLD", 10, int),
    "health_cooldown_seconds": Tunable("HEALTH_COOLDOWN_SECONDS", 60, int),
    "reaper_stale_heartbeat_s": Tunable("REAPER_STALE_HEARTBEAT_S", 90, int),
    "reaper_stale_pending_s": Tunable("REAPER_STALE_PENDING_S", 300, int),
    "reaper_stale_processing_s": Tunable("REAPER_STALE_PROCESSING_S", 3600, int),
    "reaper_scan_per_agent": Tunable("REAPER_SCAN_PER_AGENT", 20, int),
    "registry_refresh_timeout": Tunable("FRAMEWORK_REGISTRY_REFRESH_TIMEOUT", 5.0, float),
    "registry_snapshot_ttl": Tunable("FRAMEWORK_REGISTRY_SNAPSHOT_TTL", 15.0, float),
    "agent_embedding_model": Tunable("AGENT_EMBEDDING_MODEL", "gemini-embedding-001", str),
    "public_host_url": Tunable("PUBLIC_HOST_URL", "http://localhost:8000", str),
    "public_mcp_url": Tunable("PUBLIC_MCP_URL", "http://localhost:8002/mcp", str),
}

_OVERRIDE_PREFIX = "tunable_"
_CACHE_TTL_SECONDS = 30.0

_overrides: dict[str, Any] = {}
_overrides_checked_at: float = float("-inf")
_refresh_in_flight: bool = False


def _cast(value: Any, typ: type) -> Any:
    """Cast to the declared type, raising (TypeError, ValueError) on a bad value."""
    return typ(value)


def _env_default(spec: Tunable) -> Any:
    """The env-var value (cast) when set, else the built-in default. A bad env value falls
    back to the built-in default rather than raising."""
    raw = os.getenv(spec.env_var)
    if raw is None or not raw.strip():
        return spec.default
    try:
        return _cast(raw.strip(), spec.type)
    except (TypeError, ValueError):
        logger.warning("Ignoring non-%s value in %s; using built-in default", spec.type.__name__, spec.env_var)
        return spec.default


def env_default(name: str) -> Any:
    """The effective default for ``name`` ignoring any etcd override (env var > built-in)."""
    return _env_default(TUNABLES[name])


def coerce(name: str, value: Any) -> Any:
    """Cast ``value`` to ``name``'s declared type. Raises (TypeError, ValueError) when the
    value does not parse -- used by the Admin UI to validate submissions."""
    return _cast(value, TUNABLES[name].type)


def effective(name: str, override: Any) -> Any:
    """Resolve ``name`` from a known override: override (cast) > env var > built-in default.
    A bad override cast falls through to the env/default layer rather than raising."""
    spec = TUNABLES[name]
    if override is not None:
        try:
            return _cast(override, spec.type)
        except (TypeError, ValueError):
            logger.warning("Ignoring malformed %s override for %r", spec.type.__name__, name)
    return _env_default(spec)


def _refresh_overrides_sync() -> None:
    """Runs in a thread-pool worker via loop.run_in_executor -- never awaited directly.

    Reads every override with a raw, non-retrying etcd get. All-or-nothing: on any read
    error the previous cache is retained (and the TTL still gates the next attempt), so a
    blipping etcd never empties a working cache or storms it with retries.
    """
    global _overrides, _overrides_checked_at, _refresh_in_flight
    mgr = get_identity_manager()
    values: dict[str, Any] = {}
    try:
        for name in TUNABLES:
            override = mgr.get_tunable(name)
            if override is not None:
                values[name] = override
    except Exception as e:
        logger.warning("Failed to refresh tunable overrides from etcd: %s; keeping previous cache", e)
    else:
        _overrides = values
    finally:
        _overrides_checked_at = time.monotonic()
        _refresh_in_flight = False


def _kick_refresh() -> None:
    global _refresh_in_flight
    # An edge node has no etcd by design (it is a standalone install). Attempting the
    # refresh there only logs a permanent warning every TTL; env/defaults are the whole
    # story on that side.
    if os.getenv("TRELLIS_EDGE_MODE"):
        return
    if (time.monotonic() - _overrides_checked_at) < _CACHE_TTL_SECONDS:
        return
    if _refresh_in_flight:
        return
    _refresh_in_flight = True
    try:
        asyncio.get_running_loop().run_in_executor(None, _refresh_overrides_sync)
    except RuntimeError:
        # No running loop (e.g. a sync thread/tests) -- skip this refresh cycle rather than
        # block; the next call from an async context will pick it up.
        _refresh_in_flight = False


def resolve(name: str) -> Any:
    """Effective value for ``name``: etcd override > env var > built-in default, cast to
    the declared type. Cheap on hot paths (short TTL cache) and never raises when etcd is
    down -- it serves the last-known cache, or the env/default when nothing is cached yet."""
    _kick_refresh()
    return effective(name, _overrides.get(name))


def set_tunable(name: str, value: Any, identity_mgr: Optional[Any] = None) -> None:
    """Persist an override at ``/config/framework/tunable_<name>`` (Admin Dashboard)."""
    (identity_mgr or get_identity_manager()).set_tunable(name, value)


def clear_tunable(name: str, identity_mgr: Optional[Any] = None) -> None:
    """Remove an override, reverting ``name`` to its env/default (Admin Dashboard)."""
    (identity_mgr or get_identity_manager()).clear_tunable(name)
