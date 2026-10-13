# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import os
from typing import Optional

# Framework bootstrap secrets that must never leak into a spawned subprocess.
#
# This is a denylist of the framework's OWN reserved names. It cannot enumerate
# arbitrary operator secrets that live in the host process env — notably webhook
# secrets configured via the `env:<NAME>` form (core/background/webhooks.py),
# which read any env var by name. Prefer the etcd-backed `secret:<name>` form for
# those; env-based webhook secrets remain a documented exception to this scrub.
FRAMEWORK_SECRET_ENV: frozenset[str] = frozenset({
    "SESSION_SECRET", "ENCRYPTION_KEY",
    "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET",
    "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_METADATA_URL",
    "ADMIN_USERS", "ALLOWED_DOMAINS",
    "GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
    "HINDSIGHT_API_LLM_API_KEY", "HINDSIGHT_LLM_API_KEY",
    "HINDSIGHT_API_EMBEDDINGS_GEMINI_API_KEY",
})


def sanitized_env(base: Optional[dict] = None) -> dict:
    """Copy of os.environ (or `base`) with the framework's reserved secret vars removed.

    A denylist (not a whitelist) so operator-set env vars keep working; anything a
    tool legitimately needs is injected afterward via the identity-scoped secret store.
    """
    src = dict(os.environ) if base is None else dict(base)
    return {k: v for k, v in src.items() if k.upper() not in FRAMEWORK_SECRET_ENV}
