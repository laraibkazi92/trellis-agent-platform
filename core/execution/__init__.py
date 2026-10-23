# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Execution isolation: every tool/MCP/console run is its own container.

The public surface is deliberately small -- callers name a registered target and
a body of stdin, never an image, mount, network or capability. ``RunnerClient``
is the only client; ``core.execution.spec`` is the only place a container spec
is derived from a manifest.
"""

__all__ = ["RunnerClient", "RunnerUnavailable"]


def __getattr__(name: str):
    # Lazy, so importing a dependency-free submodule (``netprofiles``, used by the
    # host-side ``scripts/setup-network-profiles.sh``) does not pull in httpx.
    if name in __all__:
        from core.execution import client

        return getattr(client, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
