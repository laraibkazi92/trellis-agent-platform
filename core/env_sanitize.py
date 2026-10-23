# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import os
from typing import Optional

from core.llm_providers import FRAMEWORK_PROVIDER_KEY_ENV

# Framework bootstrap secrets that must never leak into a spawned subprocess.
#
# This is a denylist of the framework's OWN reserved names. It cannot enumerate
# arbitrary operator secrets that live in the host process env — notably webhook
# secrets configured via the `env:<NAME>` form (core/background/webhooks.py),
# which read any env var by name. Prefer the etcd-backed `secret:<name>` form for
# those; env-based webhook secrets remain a documented exception to this scrub.
# Provider credential names are derived from the registry (core/llm_providers.py).
# OLLAMA_BASE_URL stays out: it is an endpoint, not a credential, and build_provider always passes it explicitly.
FRAMEWORK_SECRET_ENV: frozenset[str] = frozenset({
    "SESSION_SECRET", "ENCRYPTION_KEY",
    "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET",
    "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_METADATA_URL",
    "ADMIN_USERS", "ALLOWED_DOMAINS",
    "HINDSIGHT_API_LLM_API_KEY", "HINDSIGHT_LLM_API_KEY",
    "HINDSIGHT_API_EMBEDDINGS_GEMINI_API_KEY",
    # v0.6 execution isolation: the runner bearer and the agent-token HMAC key are
    # control-plane credentials. They must never reach a tool, session or console
    # container, even if an operator exports them in a service's environment.
    "AGENT_TOKEN_SECRET", "RUNNER_TOKEN", "EDGE_PRIVATE_KEY_PATH",
}) | FRAMEWORK_PROVIDER_KEY_ENV


def sanitized_env(base: Optional[dict] = None) -> dict:
    """Copy of os.environ (or `base`) with the framework's reserved secret vars removed.

    A denylist (not a whitelist) so operator-set env vars keep working; anything a
    tool legitimately needs is injected afterward via the identity-scoped secret store.
    """
    src = dict(os.environ) if base is None else dict(base)
    return {k: v for k, v in src.items() if k.upper() not in FRAMEWORK_SECRET_ENV}
