# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import json
import secrets
import logging
import time
import random
import re
import contextvars
import asyncio
import hashlib
import jwt
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple, Union
from functools import wraps

from core.models import Identity, IdentityType

import pyetcd
from fastapi import Request, HTTPException
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

auth_token_var = contextvars.ContextVar("auth_token", default=None)
user_id_var = contextvars.ContextVar("user_id", default=None)
# v0.6: the short-lived HMAC token proving (agent, user, run) to the hub, relay and
# runner. Minted once per run; read by every tool wrapper.
agent_token_var = contextvars.ContextVar("agent_token", default=None)
run_id_var = contextvars.ContextVar("run_id", default=None)

# Sentinel stamped into auth_token_var for a DEV_MODE request that presented no bearer
# token. It marks "the caller is the dev user"; it is NOT a credential and must never
# be forwarded downstream as an Authorization header (see core.gateway.use_agent).
# A downstream service cannot tell a sentinel from a real key: the presence of a
# "Bearer " header makes it skip its own DEV_MODE bypass, validate the sentinel as a
# key, and reject the call with 401.
DEV_MODE_AUTH_TOKEN = "dev-token"

# Edge (trellis-proxy) registry layout. `/registry/edges/<site>/config` is the site
# record, `/status` is written by the relay, and `/edge_tokens/<sha256> -> site` is a
# token index so the relay's pre-upgrade handshake is one get instead of a scan of
# every site. Only the hash is ever persisted; the plaintext is returned once.
EDGES_PREFIX = "/registry/edges/"
EDGE_TOKENS_PREFIX = "/edge_tokens/"
EDGE_TOOLS_PREFIX = "/registry/tools/"
# MCP servers the relay publishes for a site, and the tool embeddings under
# `/registry/tools/mcp__<site>__<mcp>__<tool>` that go with them.
EDGE_MCPS_PREFIX = "/registry/mcps/"
EDGE_MANAGED_BY = "edge-relay"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _edge_token_preview(site: str, token: str) -> str:
    return f"edge_{site}_...{token[-4:]}"


def _mint_edge_token(site: str) -> Tuple[str, str]:
    """Mint an enrollment token and its storage hash (the plaintext is shown once)."""
    token = f"edge_{site}_{secrets.token_urlsafe(32)}"
    return token, hashlib.sha256(token.encode("utf-8")).hexdigest()


_EDGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def _validated_edge_name(name: Any) -> str:
    """Validate a site id, raising ``ValueError`` (the admin UI's error channel).

    Mirrors ``services/edge_relay/protocol.py``'s ``validate_site_name`` deliberately:
    ``core`` must not import ``services``. The rule has to match exactly, because a
    name the registry accepts must never be rejected later by the relay's handshake.
    """
    if not isinstance(name, str) or not _EDGE_NAME_RE.match(name):
        raise ValueError(f"Invalid edge name: {name!r}")
    if "__" in name:
        # `<site>__<tool>` is the registry key: a separator inside either half makes
        # two different (site, tool) pairs collide.
        raise ValueError(f"Edge name may not contain '__': {name!r}")
    if name.lower() == "mcp":
        # `mcp__` is already a meaningful prefix for MCP tools in core/tool_search.py.
        raise ValueError("'mcp' is reserved for MCP tool names")
    return name


class EtcdContentionError(RuntimeError):
    """Raised when an etcd compare-and-swap loop (see
    IdentityManager._atomic_update_config_list) exhausts its retry budget due to
    sustained write contention. Callers must treat this as a failed update -- the
    list was NOT modified -- rather than assume success."""

def _get_encryption_key() -> bytes:
    import base64
    raw_key = os.getenv("ENCRYPTION_KEY") or os.getenv("SESSION_SECRET")
    if not raw_key:
        dev_mode = os.getenv("DEV_MODE", "false").lower() == "true"
        if dev_mode:
            logger.warning("Using insecure static encryption key. Do not use in production.")
            raw_key = "fallback-static-development-secret-key-32-bytes"
        else:
            raise ValueError("Critical Security Error: ENCRYPTION_KEY or SESSION_SECRET must be set in the environment for production.")
    hashed = hashlib.sha256(raw_key.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(hashed)

def _encrypt_string(plaintext: str) -> str:
    if not plaintext:
        return plaintext
    from cryptography.fernet import Fernet
    f = Fernet(_get_encryption_key())
    return f.encrypt(plaintext.encode('utf-8')).decode('utf-8')

def _decrypt_string(ciphertext: str) -> str:
    if not ciphertext:
        return ciphertext
    try:
        from cryptography.fernet import Fernet
        f = Fernet(_get_encryption_key())
        return f.decrypt(ciphertext.encode('utf-8')).decode('utf-8')
    except Exception:
        # Fallback for values stored before encryption was introduced
        logger.warning("Decryption failed — returning value as-is (may be unencrypted legacy data)")
        return ciphertext

def _reject_trailing_underscore(name: str, what: str) -> None:
    """Refuse a registry name that ends with ``_`` at the write boundary.

    A trailing underscore is a legal name character, but no reference form can express
    it: ``<site>__<tool>`` and ``mcp__<server>__<tool>`` are separated by ``__``, so a
    segment ending in ``_`` makes the boundary ambiguous (``a___b`` reads as site ``a_``
    or as name ``_b`` depending on the split direction). Publishing such a name would
    leave an entry that exists, works, and can never be named by an agent manifest --
    refused where the name is written instead (sync skips it with a warning).
    """
    if name.endswith("_"):
        raise ValueError(
            f"{what} name '{name}' may not end with '_': no unambiguous '__'-separated "
            f"reference form exists for it (end with a letter, digit or '-')."
        )


def retry_etcd(max_retries=10, delay=2):
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(self, *args, **kwargs)
                except EtcdContentionError:
                    # The CAS loop already spent its own backoff-driven retry budget; re-running
                    # it here would only multiply attempts (and hold the caller for ~20s).
                    raise
                except ValueError:
                    # Input validation (e.g. an illegal registry name), not a transient
                    # etcd fault: retrying cannot succeed, so fail fast.
                    raise
                except Exception as e:
                    # Fast-fail immediately on non-transient resource exhaustion (e.g. gRPC message > 4MB)
                    err_str = str(e)
                    if "RESOURCE_EXHAUSTED" in err_str:
                        logger.error(f"etcd operation failed with RESOURCE_EXHAUSTED (payload too large). Fast-failing without retry: {e}")
                        raise
                    logger.warning(f"etcd operation failed (attempt {attempt + 1}/{max_retries}): {e}")
                    if attempt == max_retries - 1:
                        logger.error(f"etcd operation failed after {max_retries} attempts.")
                        raise
                    time.sleep(delay)
        return wrapper
    return decorator

class IdentityManager:
    def __init__(self, host: str = "127.0.0.1", port: int = 2379):
        self.client = pyetcd.client(host=host, port=port)

    @retry_etcd()
    def _get_kv(self, path: str, decrypt: bool = False) -> Optional[Any]:
        """Base method to fetch and optionally decrypt/parse a KV pair."""
        value, _ = self.client.get(path)
        if value:
            decoded = value.decode('utf-8')
            try:
                if decrypt:
                    decoded = _decrypt_string(decoded)
                return json.loads(decoded)
            except Exception as e:
                logger.error(f"Failed to parse KV at {path}: {e}")
                return None
        return None

    @retry_etcd()
    def _set_kv(self, path: str, value: Any, encrypt: bool = False) -> None:
        """Base method to serialized and optionally encrypt/store a KV pair."""
        serialized = json.dumps(value)
        if encrypt:
            serialized = _encrypt_string(serialized)
        self.client.put(path, serialized)

    def get_identity_config(self, identity: Union[Identity, str], category: str, keys: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Scoped config resolver.
        Fetches secrets or variables for any identity (User, Agent, System).
        """
        if isinstance(identity, str):
            identity = Identity.from_string(identity)
        
        path = identity.get_etcd_path(category)
        decrypt = (category == "secrets")
        
        config = self._get_kv(path, decrypt=decrypt) or {}
        
        if keys:
            return {k: v for k, v in config.items() if k in keys}
        return config

    def save_identity_config(self, identity: Union[Identity, str], category: str, data: Dict[str, Any]) -> None:
        """Saves secrets or variables for an identity."""
        if isinstance(identity, str):
            identity = Identity.from_string(identity)
            
        path = identity.get_etcd_path(category)
        encrypt = (category == "secrets")
        self._set_kv(path, data, encrypt=encrypt)

    def get_resolved_config(self, identity: Union[Identity, str], category: str, keys: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Resolves config by merging Global (System) config with Identity config.
        Identity config takes precedence.
        """
        if isinstance(identity, str):
            identity = Identity.from_string(identity)
            
        system_identity = Identity(id="system", type=IdentityType.SYSTEM)
        
        # Don't merge if we are already asking for system config
        if identity.type == IdentityType.SYSTEM:
            return self.get_identity_config(identity, category, keys)
            
        system_config = self.get_identity_config(system_identity, category)
        identity_config = self.get_identity_config(identity, category)
        
        resolved = {**system_config, **identity_config}
        
        if keys:
            return {k: v for k, v in resolved.items() if k in keys}
        return resolved

    # --- Framework LLM provider keys (Admin -> LLM Providers) ---
    # Stored encrypted at /identities/system/system/llm_keys. Deliberately NOT in the
    # "secrets" category: tool/workflow subprocesses receive the system "secrets" merge
    # via get_resolved_config, and the framework's private LLM keys must never be
    # injected into tool code. This store is read only by core.llm_factory.

    def get_llm_provider_keys(self) -> Dict[str, str]:
        """Return the decrypted framework LLM provider keys, or {} when unset.

        Keys live in their own encrypted store (see the comment above) so they are
        never merged into the tool/workflow secrets namespace.
        """
        path = Identity(id="system", type=IdentityType.SYSTEM).get_etcd_path("llm_keys")
        return self._get_kv(path, decrypt=True) or {}

    def save_llm_provider_keys(self, keys: Dict[str, str]) -> None:
        """Persist the framework LLM provider keys, encrypting them at rest."""
        path = Identity(id="system", type=IdentityType.SYSTEM).get_etcd_path("llm_keys")
        self._set_kv(path, keys, encrypt=True)

    @retry_etcd()
    def upsert_user(self, user_id: str, profile: Dict) -> None:
        """Create or update a user profile."""
        self.client.put(f"/users/profiles/{user_id}", json.dumps(profile))
        
    @retry_etcd()
    def get_user(self, user_id: str) -> Optional[Dict]:
        """Retrieve a user profile."""
        value, metadata = self.client.get(f"/users/profiles/{user_id}")
        if value:
            return json.loads(value.decode('utf-8'))
        return None

    @retry_etcd()
    def create_key(self, user_id: str, key_name: str) -> str:
        """Create a new API key for a user (v2 hashed storage)."""
        api_key = f"tl_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        key_preview = api_key[:6] + "..." + api_key[-4:]
        
        key_data = {
            "user_id": user_id,
            "name": key_name,
            "key_preview": key_preview,
            "key_hash": key_hash,
            "version": "v2"
        }
        
        self.client.put(f"/keys_v2/{key_hash}", json.dumps(key_data))
        self.client.put(f"/user_keys_v2/{user_id}/{key_hash}", "1")
        return api_key

    @retry_etcd()
    def list_keys(self, user_id: str) -> List[Dict]:
        """List all API keys for a user efficiently using secondary index."""
        keys = []
        
        for value, metadata in self.client.get_prefix(f"/user_keys_v2/{user_id}/"):
            key_hash = metadata.key.decode('utf-8').split('/')[-1]
            key_data_raw, _ = self.client.get(f"/keys_v2/{key_hash}")
            if key_data_raw:
                try:
                    data = json.loads(key_data_raw.decode('utf-8'))
                    data["key_masked"] = data.get("key_preview", "***")
                    data["key_id"] = key_hash
                    keys.append(data)
                except Exception as e:
                    logger.warning(f"Failed to process v2 key record for user {user_id}: {e}")
        return keys

    @retry_etcd()
    def delete_key_by_id(self, key_id: str) -> bool:
        """Revoke an API key using its SHA256 hash."""
        value, _ = self.client.get(f"/keys_v2/{key_id}")
        if value:
            data = json.loads(value.decode('utf-8'))
            user_id = data.get("user_id")
            if user_id:
                self.client.delete(f"/user_keys_v2/{user_id}/{key_id}")
            return self.client.delete(f"/keys_v2/{key_id}")
        return False

    @retry_etcd()
    def validate_key(self, api_key: str) -> Optional[str]:
        """Validate an API key and return the associated user_id if valid."""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        value, _ = self.client.get(f"/keys_v2/{key_hash}")
        if value:
            data = json.loads(value.decode('utf-8'))
            return data.get("user_id")
        return None

    def generate_execution_token(self, user_id: str) -> str:
        """Generate a short-lived execution token for a background agent."""
        from itsdangerous import URLSafeTimedSerializer
        serializer = URLSafeTimedSerializer(_get_encryption_key())
        return "exec_" + serializer.dumps({"user_id": user_id})

    def validate_execution_token(self, token: str) -> Optional[str]:
        """Validate a short-lived execution token and return user_id."""
        from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
        if not token.startswith("exec_"):
            return None
        token_body = token[5:]
        serializer = URLSafeTimedSerializer(_get_encryption_key())
        try:
            # 5 minutes expiration
            data = serializer.loads(token_body, max_age=300)
            return data.get("user_id")
        except (BadSignature, SignatureExpired):
            return None

    @retry_etcd()
    def get_config(self, key: str, default: Any = None) -> Any:
        """Retrieve a framework configuration value."""
        value, _ = self.client.get(f"/config/framework/{key}")
        if value:
            return json.loads(value.decode('utf-8'))
        return default

    @retry_etcd()
    def set_config(self, key: str, value: Any) -> None:
        """Set a framework configuration value."""
        self.client.put(f"/config/framework/{key}", json.dumps(value))

    def get_disabled_standard_agents(self) -> List[str]:
        """Retrieve the list of disabled standard agents.

        Not itself @retry_etcd()-decorated: get_config() already retries. Stacking a
        second retry layer on top of it multiplies worst-case retry time (10x10 attempts,
        ~200+s) instead of adding to it -- see get_agent_memory_enabled above for the
        same pattern."""
        return self.get_config("disabled_standard_agents", [])

    def set_disabled_standard_agents(self, agents: List[str]) -> None:
        """Set the list of disabled standard agents.

        Not itself @retry_etcd()-decorated -- see get_disabled_standard_agents above."""
        self.set_config("disabled_standard_agents", agents)

    def get_disabled_workflows(self) -> List[str]:
        """Retrieve the list of disabled workflows.

        Not itself @retry_etcd()-decorated: get_config() already retries. Stacking a
        second retry layer on top of it multiplies worst-case retry time (10x10 attempts,
        ~200+s) instead of adding to it -- see get_agent_memory_enabled above for the
        same pattern."""
        return self.get_config("disabled_workflows", [])

    def _atomic_update_config_list(self, key: str, update_fn) -> List[str]:
        """Atomically update a JSON list in /config/framework/{key} using Compare-And-Swap (CAS).

        Runs synchronously (etcd calls block) -- callers dispatch it via
        asyncio.to_thread, so the time.sleep() backoff below never blocks the event loop.

        Raises EtcdContentionError if the CAS loop exhausts its retry budget without
        ever winning the compare-and-swap. There is intentionally no blind-overwrite
        fallback: a plain put() here would silently clobber a concurrent writer's
        change and report success for an update that never safely applied.
        """
        full_key = f"/config/framework/{key}"
        max_attempts = 20
        for attempt in range(max_attempts):
            raw_val, _ = self.client.get(full_key)
            if raw_val is None:
                initial_list = update_fn([])
                new_bytes = json.dumps(initial_list).encode('utf-8')
                if self.client.put_if_not_exists(full_key, new_bytes):
                    return initial_list
            else:
                try:
                    current_list = json.loads(raw_val.decode('utf-8'))
                    if not isinstance(current_list, list):
                        current_list = []
                except Exception:
                    current_list = []
                updated_list = update_fn(list(current_list))
                new_bytes = json.dumps(updated_list).encode('utf-8')
                if self.client.replace(full_key, raw_val, new_bytes):
                    return updated_list
            # Lost the CAS race -- another writer won. Back off briefly (jittered,
            # capped small) before retrying so contention doesn't burn through all
            # 20 attempts in milliseconds.
            if attempt < max_attempts - 1:
                backoff = min(0.01, 0.002 * (2 ** attempt)) + random.uniform(0, 0.003)
                time.sleep(backoff)
        raise EtcdContentionError(
            f"Failed to atomically update '{full_key}' after {max_attempts} attempts "
            "due to sustained write contention. The list was not modified."
        )

    @retry_etcd()
    def toggle_disabled_standard_agent(self, name: str, disable: Optional[bool] = None) -> bool:
        """Atomically add or remove an agent from disabled_standard_agents using CAS.
        If disable is None, toggles. If True, disables. If False, enables.
        Returns True if the agent is now disabled, False if enabled."""
        def _update(current: List[str]) -> List[str]:
            res = list(current)
            should_disable = (name not in res) if disable is None else disable
            if should_disable and name not in res:
                res.append(name)
            elif not should_disable and name in res:
                res.remove(name)
            return res

        final_list = self._atomic_update_config_list("disabled_standard_agents", _update)
        return name in final_list

    @retry_etcd()
    def toggle_disabled_workflow(self, name: str, disable: Optional[bool] = None) -> bool:
        """Atomically add or remove a workflow from disabled_workflows using CAS.
        If disable is None, toggles. If True, disables. If False, enables.
        Returns True if the workflow is now disabled, False if enabled."""
        def _update(current: List[str]) -> List[str]:
            res = list(current)
            should_disable = (name not in res) if disable is None else disable
            if should_disable and name not in res:
                res.append(name)
            elif not should_disable and name in res:
                res.remove(name)
            return res

        final_list = self._atomic_update_config_list("disabled_workflows", _update)
        return name in final_list

    def get_agent_memory_enabled(self) -> bool:
        """Retrieve the global agent-memory feature flag (admin master switch).

        Not itself @retry_etcd()-decorated: get_config() already retries. Stacking a
        second retry layer on top of it multiplies worst-case retry time (10x10 attempts,
        ~200+s) instead of adding to it -- see get_rules_evaluation_timeout below for the
        same pattern."""
        return bool(self.get_config("agent_memory_enabled", False))

    def set_agent_memory_enabled(self, enabled: bool) -> None:
        """Set the global agent-memory feature flag (admin master switch).

        Not itself @retry_etcd()-decorated -- see get_agent_memory_enabled above."""
        self.set_config("agent_memory_enabled", bool(enabled))

    def get_agent_memory_isolated_per_user(self) -> bool:
        """Retrieve the per-user agent-memory isolation flag. When on, memory banks
        are keyed "{agent_name}:{user_id}" instead of the agent name alone.

        Not itself @retry_etcd()-decorated: get_config() already retries. Stacking a
        second retry layer on top of it multiplies worst-case retry time (10x10 attempts,
        ~200+s) instead of adding to it -- see get_agent_memory_enabled above for the
        same pattern."""
        return bool(self.get_config("agent_memory_isolated_per_user", False))

    def set_agent_memory_isolated_per_user(self, enabled: bool) -> None:
        """Set the per-user agent-memory isolation flag.

        Not itself @retry_etcd()-decorated -- see get_agent_memory_isolated_per_user above."""
        self.set_config("agent_memory_isolated_per_user", bool(enabled))

    def get_rules_evaluation_timeout(self) -> Optional[float]:
        """Retrieve the admin-configured Trellis Rules Engine LLM evaluation timeout
        (seconds), or None if never set -- callers fall back to the
        RULES_EVALUATION_TIMEOUT env var default in that case.

        Not itself @retry_etcd()-decorated: get_config() already retries. Stacking a
        second retry layer on top of it multiplies worst-case retry time (10x10 attempts)
        instead of adding to it -- get_agent_memory_enabled/set_agent_memory_enabled above
        were normalized to this same single-retry-layer pattern (they used to double up
        the decorator; fixed alongside this rules-engine work)."""
        value = self.get_config("rules_evaluation_timeout", None)
        return float(value) if value is not None else None

    def set_rules_evaluation_timeout(self, timeout_seconds: float) -> None:
        """Set the admin-configured Trellis Rules Engine LLM evaluation timeout (seconds).

        Not itself @retry_etcd()-decorated -- see get_rules_evaluation_timeout above."""
        self.set_config("rules_evaluation_timeout", float(timeout_seconds))

    @retry_etcd()
    def clear_config(self, key: str) -> None:
        """Delete a framework configuration value from etcd, reverting it to its default."""
        self.client.delete(f"/config/framework/{key}")

    @retry_etcd()
    def clear_rules_evaluation_timeout(self) -> None:
        """Remove the admin override, reverting to the RULES_EVALUATION_TIMEOUT env var default."""
        self.client.delete("/config/framework/rules_evaluation_timeout")

    def clear_default_llm_provider(self) -> None:
        """Remove the framework default provider, reverting to model-name inference.

        Not itself @retry_etcd()-decorated: clear_config() already retries."""
        self.clear_config("default_llm_provider")

    def clear_default_llm_model(self) -> None:
        """Remove the framework default model.

        Not itself @retry_etcd()-decorated -- see clear_default_llm_provider above."""
        self.clear_config("default_llm_model")

    def clear_default_llm_base_url(self) -> None:
        """Remove the framework default base_url.

        Not itself @retry_etcd()-decorated -- see clear_default_llm_provider above."""
        self.clear_config("default_llm_base_url")

    def get_rules_evaluation_provider(self) -> Optional[str]:
        """Retrieve the admin-configured provider for the Rules Engine LLM decider,
        or None if never set -- callers fall back to the RULES_EVALUATION_PROVIDER
        env var / model-name inference in that case.

        Not itself @retry_etcd()-decorated: get_config() already retries -- see
        get_rules_evaluation_timeout above for the single-retry-layer rationale."""
        value = self.get_config("rules_evaluation_provider", None)
        return str(value) if value is not None else None

    def set_rules_evaluation_provider(self, provider: str) -> None:
        """Set the admin-configured provider for the Rules Engine LLM decider.

        Not itself @retry_etcd()-decorated -- see get_rules_evaluation_provider above."""
        self.set_config("rules_evaluation_provider", str(provider))

    def get_rules_evaluation_base_url(self) -> Optional[str]:
        """Retrieve the admin-configured base_url for the Rules Engine LLM decider
        (used by the 'openai-compatible' provider), or None if never set --
        callers fall back to the RULES_EVALUATION_BASE_URL env var in that case.

        Not itself @retry_etcd()-decorated: get_config() already retries -- see
        get_rules_evaluation_timeout above for the single-retry-layer rationale."""
        value = self.get_config("rules_evaluation_base_url", None)
        return str(value) if value is not None else None

    def set_rules_evaluation_base_url(self, base_url: str) -> None:
        """Set the admin-configured base_url for the Rules Engine LLM decider.

        Not itself @retry_etcd()-decorated -- see get_rules_evaluation_base_url above."""
        self.set_config("rules_evaluation_base_url", str(base_url))

    def get_rules_evaluation_model(self) -> Optional[str]:
        """Retrieve the admin-configured model for the Rules Engine LLM decider, or None
        if never set -- callers fall back to the RULES_EVALUATION_MODEL env var default.

        Not itself @retry_etcd()-decorated -- see get_rules_evaluation_provider above."""
        value = self.get_config("rules_evaluation_model", None)
        return str(value) if value is not None else None

    def set_rules_evaluation_model(self, model: str) -> None:
        """Set the admin-configured model for the Rules Engine LLM decider.

        Not itself @retry_etcd()-decorated -- see get_rules_evaluation_model above."""
        self.set_config("rules_evaluation_model", str(model))

    def get_default_llm_provider(self) -> Optional[str]:
        """Retrieve the admin-configured framework default LLM provider, or None if never
        set -- agents/workflows that name neither a provider nor a model inherit it.

        Not itself @retry_etcd()-decorated: get_config() already retries -- see
        get_rules_evaluation_timeout above for the single-retry-layer rationale."""
        value = self.get_config("default_llm_provider", None)
        return str(value) if value is not None else None

    def set_default_llm_provider(self, provider: str) -> None:
        """Set the framework default LLM provider.

        Not itself @retry_etcd()-decorated -- see get_default_llm_provider above."""
        self.set_config("default_llm_provider", str(provider))

    def get_default_llm_model(self) -> Optional[str]:
        """Retrieve the admin-configured framework default LLM model, or None if never set.

        Not itself @retry_etcd()-decorated -- see get_default_llm_provider above."""
        value = self.get_config("default_llm_model", None)
        return str(value) if value is not None else None

    def set_default_llm_model(self, model: str) -> None:
        """Set the framework default LLM model.

        Not itself @retry_etcd()-decorated -- see get_default_llm_provider above."""
        self.set_config("default_llm_model", str(model))

    def get_default_llm_base_url(self) -> Optional[str]:
        """Retrieve the admin-configured framework default LLM base_url, or None if never set.

        Not itself @retry_etcd()-decorated -- see get_default_llm_provider above."""
        value = self.get_config("default_llm_base_url", None)
        return str(value) if value is not None else None

    def set_default_llm_base_url(self, base_url: str) -> None:
        """Set the framework default LLM base_url.

        Not itself @retry_etcd()-decorated -- see get_default_llm_provider above."""
        self.set_config("default_llm_base_url", str(base_url))

    def get_rules_confidence_threshold(self) -> Optional[float]:
        """Retrieve the admin-configured confidence threshold for the Rules Engine decider,
        or None if never set -- callers fall back to the RULES_CONFIDENCE_THRESHOLD env var
        default.

        Not itself @retry_etcd()-decorated -- see get_rules_evaluation_provider above."""
        value = self.get_config("rules_confidence_threshold", None)
        return float(value) if value is not None else None

    def set_rules_confidence_threshold(self, threshold: float) -> None:
        """Set the admin-configured confidence threshold for the Rules Engine decider.

        Not itself @retry_etcd()-decorated -- see get_rules_confidence_threshold above."""
        self.set_config("rules_confidence_threshold", float(threshold))

    # --- Whitelabel / Branding ---
    # One override per key, stored at /config/framework/app_<key>. The admin UI
    # (Admin Dashboard -> Branding) is the primary editing surface; the APP_* env vars
    # only seed the defaults defined in core/dependencies.py.
    BRANDING_KEYS = (
        "name",
        "favicon_url",
        "logo_url",
        "login_logo_url",
        "login_title",
        "login_subtitle",
        "login_disclaimer",
        "accent_color",
        "accent_color_dark",
    )

    def get_branding(self, key: str) -> Optional[str]:
        """Read one branding override from etcd, or None when never set via the UI -- the
        caller then falls back to that key's APP_* env default.

        Deliberately NOT @retry_etcd()-decorated, and not routed through get_config():
        this feeds the per-render Jinja context processor, where a fast failure that falls
        back to defaults beats a multi-second retry storm against a blipping etcd."""
        if key not in self.BRANDING_KEYS:
            raise ValueError(f"Unknown branding key '{key}'")
        value, _ = self.client.get(f"/config/framework/app_{key}")
        if value:
            return value.decode("utf-8")
        return None

    def set_branding(self, key: str, value: str) -> None:
        """Persist one branding override to etcd.

        Not itself @retry_etcd()-decorated -- see get_branding above."""
        if key not in self.BRANDING_KEYS:
            raise ValueError(f"Unknown branding key '{key}'")
        self.set_config(f"app_{key}", str(value))

    @retry_etcd()
    def clear_branding(self, key: str) -> None:
        """Remove a branding override, reverting that key to its env-seeded default."""
        if key not in self.BRANDING_KEYS:
            raise ValueError(f"Unknown branding key '{key}'")
        self.client.delete(f"/config/framework/app_{key}")

    # --- Runtime Tunables (Admin Dashboard -> Limits & Tuning) ---
    # One override per tunable, stored at /config/framework/tunable_<name>. The registry of
    # valid names/defaults/types lives in core/tunables.py (not imported here to avoid a
    # cycle); these accessors are the etcd seam it resolves through.

    def get_tunable(self, name: str) -> Optional[Any]:
        """Read one runtime tunable override from etcd, or None when never set -- the
        caller then falls back to that tunable's env var / built-in default.

        Deliberately NOT @retry_etcd()-decorated, and not routed through get_config():
        this feeds the background refresh behind hot request paths, where a fast failure
        that keeps the last-known cache beats a multi-second retry storm against a blipping
        etcd. Values are stored as JSON so typed tunables round-trip."""
        value, _ = self.client.get(f"/config/framework/tunable_{name}")
        if not value:
            return None
        try:
            return json.loads(value.decode("utf-8"))
        except Exception as e:
            logger.warning(f"Failed to parse tunable override at tunable_{name}: {e}")
            return None

    def set_tunable(self, name: str, value: Any) -> None:
        """Set a runtime tunable override.

        Not itself @retry_etcd()-decorated: set_config() already retries."""
        self.set_config(f"tunable_{name}", value)

    def clear_tunable(self, name: str) -> None:
        """Remove a runtime tunable override, reverting it to its env/default.

        Not itself @retry_etcd()-decorated: clear_config() already retries."""
        self.clear_config(f"tunable_{name}")

    # --- Registry Methods for Agents and Tools ---

    @retry_etcd()
    def save_agent_config(self, name: str, config: Dict) -> None:
        self.client.put(f"/registry/agents/{name}/config", json.dumps(config))

    @retry_etcd()
    def get_agent_config(self, name: str) -> Optional[Dict]:
        value, _ = self.client.get(f"/registry/agents/{name}/config")
        if value:
            return json.loads(value.decode('utf-8'))
        return None

    @retry_etcd()
    def save_agent_skills(self, name: str, skills: str) -> None:
        self.client.put(f"/registry/agents/{name}/skills", skills)

    @retry_etcd()
    def get_agent_skills(self, name: str) -> Optional[str]:
        value, _ = self.client.get(f"/registry/agents/{name}/skills")
        if value:
            return value.decode('utf-8')
        return None

    @retry_etcd()
    def save_agent_embedding(self, name: str, vector: List[float]) -> None:
        """Persist an agent's description embedding for semantic search."""
        self.client.put(f"/registry/agents/{name}/embedding", json.dumps(vector))

    def _get_all_embeddings_by_prefix(self, prefix: str) -> Dict[str, List[float]]:
        """Helper to bulk-fetch every cached embedding vector under a registry prefix."""
        embeddings: Dict[str, List[float]] = {}
        suffix = "/embedding"
        for value, metadata in self.client.get_prefix(prefix):
            key_str = metadata.key.decode('utf-8')
            if key_str.startswith(prefix) and key_str.endswith(suffix) and value:
                name = key_str[len(prefix):-len(suffix)]
                if name:
                    try:
                        embeddings[name] = json.loads(value.decode('utf-8'))
                    except json.JSONDecodeError:
                        pass
        return embeddings

    def _list_names_by_prefix(self, prefix: str) -> List[str]:
        """Helper to list the first path segment of every key under a registry prefix."""
        names = set()
        for value, metadata in self.client.get_prefix(prefix):
            key_str = metadata.key.decode('utf-8')
            if key_str.startswith(prefix):
                rest = key_str[len(prefix):]
                name = rest.split('/')[0]
                if name:
                    names.add(name)
        return list(names)

    @retry_etcd()
    def get_all_agent_embeddings(self) -> Dict[str, List[float]]:
        """Bulk-fetch every agent's cached embedding vector, keyed by agent name."""
        return self._get_all_embeddings_by_prefix("/registry/agents/")

    @retry_etcd()
    def list_agents(self) -> List[str]:
        """List all agent names in the registry."""
        return self._list_names_by_prefix("/registry/agents/")

    @retry_etcd()
    def save_tool_config(self, name: str, config: Dict) -> None:
        # Only an edge tool's name is a reference segment (`<site>__<tool>`); a central
        # tool is addressed by its bare name, so a trailing `_` stays legal there.
        if (config or {}).get("managed_by") == "edge-relay":
            _reject_trailing_underscore(name, "edge tool")
        self.client.put(f"/registry/tools/{name}/config", json.dumps(config))

    @retry_etcd()
    def get_tool_config(self, name: str) -> Optional[Dict]:
        value, _ = self.client.get(f"/registry/tools/{name}/config")
        if value:
            return json.loads(value.decode('utf-8'))
        return None

    def get_tool_config_safe(self, name: str) -> Tuple[bool, Optional[Dict]]:
        """Read one tool config for the hub's reconcile pass: ``(read_ok, config)``.

        Deliberately undecorated. ``get_tool_config`` is wrapped in ``retry_etcd``,
        which retries *any* exception -- a single malformed JSON value would cost the
        caller ~18 s of backoff and make the whole reconcile look like a registry
        outage. Here a decode failure is reported as ``read_ok=False`` immediately, and
        the caller protects that tool from the prune instead of deleting it.
        """
        try:
            value, _ = self.client.get(f"/registry/tools/{name}/config")
        except Exception as exc:
            logger.warning(f"Could not read tool config '{name}': {exc}")
            return False, None
        if not value:
            return True, None
        try:
            decoded = json.loads(value.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            logger.error(f"Tool config '{name}' is not valid JSON; leaving it untouched.")
            return False, None
        return True, decoded if isinstance(decoded, dict) else None

    @retry_etcd()
    def list_tools(self) -> List[str]:
        """List all tool names in the registry."""
        return self._list_names_by_prefix("/registry/tools/")

    def _get_all_configs_by_prefix(self, prefix: str) -> Dict[str, Dict]:
        """Helper to fetch all configs under a given registry prefix."""
        configs = {}
        for value, metadata in self.client.get_prefix(prefix):
            key_str = metadata.key.decode('utf-8')
            if key_str.startswith(prefix) and key_str.endswith("/config") and value:
                rest = key_str[len(prefix):]
                name = rest.split('/')[0]
                if name:
                    try:
                        configs[name] = json.loads(value.decode('utf-8'))
                    except json.JSONDecodeError:
                        pass
        return configs

    @retry_etcd()
    def get_all_tool_configs(self) -> Dict[str, Dict]:
        """Get all tool configs in a single fetch."""
        return self._get_all_configs_by_prefix("/registry/tools/")

    @retry_etcd()
    def save_tool_embedding(self, name: str, vector: List[float]) -> None:
        """Persist a tool's description embedding for semantic search."""
        self.client.put(f"/registry/tools/{name}/embedding", json.dumps(vector))

    @retry_etcd()
    def get_all_tool_embeddings(self) -> Dict[str, List[float]]:
        """Bulk-fetch every tool's cached embedding vector, keyed by tool name."""
        return self._get_all_embeddings_by_prefix("/registry/tools/")

    @retry_etcd()
    def save_mcp_config(self, name: str, config: Dict) -> None:
        """Persist one MCP config.

        A **central** MCP name may not contain ``__``: the name is the middle segment of
        ``mcp__<server>__<tool>``, and a name with ``__`` inside it makes that reference
        splittable two ways (a central server ``srv`` with tool ``do__thing`` versus an
        edge site ``srv`` exporting MCP ``do``). The relay's own keys -- ``<site>__<mcp>``
        -- are the one legitimate exception, and it tags them ``managed_by: "edge-relay"``.
        """
        if "__" in name and (config or {}).get("managed_by") != "edge-relay":
            raise ValueError(
                f"MCP name '{name}' may not contain '__'; that separator is reserved "
                f"for edge '<site>__<mcp>' registry keys."
            )
        _reject_trailing_underscore(name, "MCP")
        self.client.put(f"/registry/mcps/{name}/config", json.dumps(config))

    @retry_etcd()
    def get_mcp_config(self, name: str) -> Optional[Dict]:
        value, _ = self.client.get(f"/registry/mcps/{name}/config")
        if value:
            return json.loads(value.decode('utf-8'))
        return None

    @retry_etcd()
    def list_mcps(self) -> List[str]:
        """List all MCP names in the registry."""
        return self._list_names_by_prefix("/registry/mcps/")

    @retry_etcd()
    def get_all_mcp_configs(self) -> Dict[str, Dict]:
        """Get all MCP configs in a single fetch."""
        return self._get_all_configs_by_prefix("/registry/mcps/")

    @retry_etcd()
    def delete_mcp(self, name: str) -> bool:
        """Delete an MCP config from the registry."""
        deleted = self.client.delete(f"/registry/mcps/{name}/config")
        return deleted

    @retry_etcd()
    def delete_mcp_tool_embeddings(self, mcp_name: str) -> None:
        """Prefix-delete the tool embeddings indexed for one MCP server's tools.

        Registry sync saves those vectors under the ``use_tool`` name
        ``mcp__{server}__{tool}`` -- i.e. ``/registry/tools/mcp__{server}__{tool}/embedding``
        -- so an MCP pruned from the registry must also clear that key range, or its
        embeddings outlive the config and keep ranking in tool search as ghosts.

        The range is walked instead of ``delete_prefix``: the embedding key ends with
        the *tool* name, not with ``/embedding`` directly after the server prefix, so
        only keys under the name prefix that really are embeddings are removed (a
        local tool an operator happened to name ``mcp__{server}__{tool}`` keeps its
        config).
        """
        prefix = f"/registry/tools/mcp__{mcp_name}__"
        suffix = "/embedding"
        for _value, metadata in self.client.get_prefix(prefix):
            key = metadata.key.decode("utf-8")
            if key.startswith(prefix) and key.endswith(suffix):
                self.client.delete(key)

    # --- Edges (trellis-proxy) -------------------------------------------------
    #
    # A site is /registry/edges/<site>/{config,status}; the relay is the only writer
    # of its `<site>__<tool>` tool configs, so nothing here touches those beyond
    # deleting them when the site itself is removed. Tokens are minted once, stored
    # as a SHA-256 hash, and indexed at /edge_tokens/<sha256> -> site. No method here
    # logs a token or its hash.

    def _read_edge_record(self, path: str) -> Optional[Dict]:
        """Read one edge record without a retry loop of its own.

        Public readers wrap this in ``@retry_etcd()``; mutators call it directly so a
        failing etcd is retried once rather than multiplied by nesting. A corrupt
        value reads as missing: re-running a JSON parse ten times helps nobody, and
        the edge auth path must fail closed.
        """
        value, _ = self.client.get(path)
        if not value:
            return None
        try:
            parsed = json.loads(value.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            logger.error(f"Edge record at {path} is not valid JSON; treating it as missing.")
            return None
        if not isinstance(parsed, dict):
            logger.error(f"Edge record at {path} is not a JSON object; treating it as missing.")
            return None
        return parsed

    @retry_etcd()
    def save_edge_config(self, name: str, config: Dict) -> None:
        """Persist an edge (site) record. Operator-editable fields are the admin UI's."""
        self.client.put(f"{EDGES_PREFIX}{name}/config", json.dumps(config))

    @retry_etcd()
    def get_edge_config(self, name: str) -> Optional[Dict]:
        return self._read_edge_record(f"{EDGES_PREFIX}{name}/config")

    @retry_etcd()
    def list_edges(self) -> List[str]:
        """List all registered edge (site) names."""
        return self._list_names_by_prefix(EDGES_PREFIX)

    @retry_etcd()
    def get_all_edge_configs(self) -> Dict[str, Dict]:
        """Get all edge configs in a single fetch."""
        return self._get_all_configs_by_prefix(EDGES_PREFIX)

    @retry_etcd()
    def save_edge_status(self, name: str, status: Dict) -> None:
        """Persist the relay-owned connection status for a site."""
        self.client.put(f"{EDGES_PREFIX}{name}/status", json.dumps(status))

    @retry_etcd()
    def get_edge_status(self, name: str) -> Optional[Dict]:
        return self._read_edge_record(f"{EDGES_PREFIX}{name}/status")

    def create_edge(
        self,
        name: str,
        display_name: str,
        created_by: str,
        exports: Optional[List[str]] = None,
    ) -> str:
        """Register a site and return its enrollment token (the only time it exists).

        Distinct from ``create_key``: user API keys have their own lifecycle and
        owner, and an edge token authenticates one tunnel, not a person.

        Validation and the duplicate check sit outside the retried body on purpose:
        a ``ValueError`` inside it would skip the backoff entirely (``retry_etcd``
        fast-fails on it), and the admin should see the reason immediately.
        """
        site = _validated_edge_name(name)
        if self.get_edge_config(site):
            raise ValueError(f"Edge '{site}' already exists.")
        return self._create_edge(site, display_name, created_by, exports)

    @retry_etcd()
    def _create_edge(
        self,
        site: str,
        display_name: str,
        created_by: str,
        exports: Optional[List[str]],
    ) -> str:
        token, token_hash = _mint_edge_token(site)
        config = {
            "name": site,
            "display_name": display_name or site,
            "token_hash": token_hash,
            "token_preview": _edge_token_preview(site, token),
            "version": "v1",
            "created_by": created_by,
            "created_at": _now_iso(),
            "enabled": True,
            "exports": list(exports or []),
            "public": False,
            "public_tools": [],
        }
        self.client.put(f"{EDGES_PREFIX}{site}/config", json.dumps(config))
        self.client.put(f"{EDGE_TOKENS_PREFIX}{token_hash}", json.dumps(site))
        logger.info(f"Edge '{site}' registered by {created_by}.")
        return token

    def rotate_edge_token(self, name: str, rotated_by: str) -> str:
        """Replace a site's enrollment token; everything else on the record survives.

        The config is written before the old index key is deleted: ``resolve_edge_token``
        also compares the stored hash, so the old token stops working at the config
        write, and a crash between the two leaves an inert index entry, not a live one.
        """
        config = self.get_edge_config(name)
        if not config:
            raise ValueError(f"Edge '{name}' not found.")
        return self._rotate_edge_token(name, config, rotated_by)

    @retry_etcd()
    def _rotate_edge_token(self, name: str, config: Dict, rotated_by: str) -> str:
        old_hash = config.get("token_hash")
        token, token_hash = _mint_edge_token(name)
        config.update({
            "token_hash": token_hash,
            "token_preview": _edge_token_preview(name, token),
            "version": "v1",
            # An explicit rotation is a re-enrollment, so a previously revoked site
            # becomes reachable again; otherwise there is no way back from revoke.
            "enabled": True,
            "rotated_by": rotated_by,
            "rotated_at": _now_iso(),
        })
        self.client.put(f"{EDGES_PREFIX}{name}/config", json.dumps(config))
        self.client.put(f"{EDGE_TOKENS_PREFIX}{token_hash}", json.dumps(name))
        if isinstance(old_hash, str) and old_hash:
            self.client.delete(f"{EDGE_TOKENS_PREFIX}{old_hash}")
        logger.info(f"Edge '{name}' token rotated by {rotated_by}.")
        return token

    @retry_etcd()
    def revoke_edge_token(self, name: str) -> None:
        """Disable a site by dropping its index key and clearing ``enabled``.

        ``token_hash`` is kept for audit, but a revoked site whose index entry somehow
        survives still fails to resolve: resolution requires ``enabled`` to be truthy.
        """
        config = self._read_edge_record(f"{EDGES_PREFIX}{name}/config")
        if not config:
            logger.warning(f"Edge '{name}' not found; nothing to revoke.")
            return

        token_hash = config.get("token_hash")
        config["enabled"] = False
        config["revoked_at"] = _now_iso()
        self.client.put(f"{EDGES_PREFIX}{name}/config", json.dumps(config))
        if isinstance(token_hash, str) and token_hash:
            self.client.delete(f"{EDGE_TOKENS_PREFIX}{token_hash}")
        logger.info(f"Edge '{name}' token revoked.")

    @retry_etcd()
    def resolve_edge_token(self, token: str) -> Optional[str]:
        """Resolve a bearer token to its site name, or ``None``.

        One indexed get on the hot path. Both the index entry and a truthy ``enabled``
        are required, and the stored hash must still match, so a stale index entry
        (rotation or revoke interrupted halfway) fails closed.
        """
        if not token:
            return None

        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        value, _ = self.client.get(f"{EDGE_TOKENS_PREFIX}{digest}")
        if not value:
            return None
        try:
            site = json.loads(value.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            logger.error("An edge token index entry is not valid JSON; ignoring it.")
            return None
        if not isinstance(site, str) or not site:
            return None

        config = self._read_edge_record(f"{EDGES_PREFIX}{site}/config")
        if not config or not config.get("enabled", True):
            return None
        # Both sides are SHA-256 digests of a value the caller must already know, so a
        # constant-time compare adds nothing an attacker could measure.
        if config.get("token_hash") != digest:
            logger.warning(f"Edge '{site}' token index entry is stale; refusing it.")
            return None
        return site

    @retry_etcd()
    def delete_edge(self, name: str) -> None:
        """Remove a site: index entry, config, status, and its `<site>__*` inventory.

        The token index key is deleted first. If the tool pass then fails, the retry
        re-reads an already-deleted config and would no longer know the hash to
        remove -- leaving an index entry pointing at a site that no longer exists.
        """
        config = self._read_edge_record(f"{EDGES_PREFIX}{name}/config") or {}
        token_hash = config.get("token_hash")
        if isinstance(token_hash, str) and token_hash:
            self.client.delete(f"{EDGE_TOKENS_PREFIX}{token_hash}")
        self.client.delete(f"{EDGES_PREFIX}{name}/config")
        self.client.delete(f"{EDGES_PREFIX}{name}/status")
        removed = self._delete_edge_tools(name)
        removed_mcps = self._delete_edge_mcps(name)
        logger.info(
            f"Edge '{name}' deleted along with {removed} published tool(s) "
            f"and {removed_mcps} MCP server(s)."
        )

    @retry_etcd()
    def delete_edge_tools(self, name: str) -> int:
        """Delete the tool configs and embeddings the relay published for a site."""
        return self._delete_edge_tools(name)

    @retry_etcd()
    def delete_edge_mcps(self, name: str) -> int:
        """Delete the MCP configs and tool embeddings the relay published for a site."""
        return self._delete_edge_mcps(name)

    def _delete_edge_tools(self, name: str) -> int:
        """Count and remove `<site>__*` tools, refusing anything the relay does not own."""
        from core.tool_index import delete_tool

        prefix = f"{EDGE_TOOLS_PREFIX}{name}__"
        removed = 0
        for value, metadata in self.client.get_prefix(prefix):
            key = metadata.key.decode('utf-8')
            if not key.startswith(prefix) or not key.endswith("/config"):
                continue
            tool_name = key[len(EDGE_TOOLS_PREFIX):-len("/config")]
            try:
                config = json.loads(value.decode('utf-8')) if value else {}
            except (json.JSONDecodeError, UnicodeDecodeError):
                config = None
            if not isinstance(config, dict) or config.get("managed_by") != EDGE_MANAGED_BY:
                # Never delete a tool we did not write: `<site>__` is a name prefix, not
                # proof of ownership (a local tool or an older scheme may hold it).
                logger.warning(f"Refusing to delete tool '{tool_name}': not managed by the edge relay.")
                continue
            delete_tool(self, tool_name)
            removed += 1
        return removed

    def _delete_edge_mcps(self, name: str) -> int:
        """Count and remove `<site>__*` MCP servers, refusing anything the relay does not own.

        Each config's tool embeddings live at
        ``/registry/tools/mcp__<site>__<mcp>__<tool>/embedding``; that prefix is cleared
        too, or deleting a site leaves its tools ranking in search forever. The prefix
        is written out rather than delegating to ``delete_mcp_tool_embeddings`` so the
        mutator keeps one retry loop (see ``_read_edge_record``).
        """
        prefix = f"{EDGE_MCPS_PREFIX}{name}__"
        removed = 0
        for value, metadata in self.client.get_prefix(prefix):
            key = metadata.key.decode('utf-8')
            if not key.startswith(prefix) or not key.endswith("/config"):
                continue
            mcp_name = key[len(EDGE_MCPS_PREFIX):-len("/config")]
            try:
                config = json.loads(value.decode('utf-8')) if value else {}
            except (json.JSONDecodeError, UnicodeDecodeError):
                config = None
            if not isinstance(config, dict) or config.get("managed_by") != EDGE_MANAGED_BY:
                # `<site>__` is a name prefix, not proof of ownership: a local MCP or an
                # older scheme may hold the name.
                logger.warning(
                    f"Refusing to delete MCP '{mcp_name}': not managed by the edge relay."
                )
                continue
            self.client.delete(f"{EDGE_MCPS_PREFIX}{mcp_name}/config")
            self.client.delete_prefix(f"/registry/tools/mcp__{mcp_name}__")
            removed += 1
        return removed

    @retry_etcd()
    def save_routing_rules(self, rules_data: Dict[str, Any]) -> None:
        """Persist the central Trellis Rules Engine cross-agent overrides."""
        self.client.put("/registry/routing_rules", json.dumps(rules_data))

    @retry_etcd()
    def get_routing_rules(self) -> Optional[Dict[str, Any]]:
        """Retrieve the central Trellis Rules Engine cross-agent overrides."""
        value, _ = self.client.get("/registry/routing_rules")
        if value:
            return json.loads(value.decode('utf-8'))
        return None

    @retry_etcd()
    def get_health_status(self, entity_type: str, name: str) -> Optional[Dict]:
        """Retrieve the health status of an agent or tool."""
        value, _ = self.client.get(f"/health/{entity_type}/{name}")
        if value:
            return json.loads(value.decode('utf-8'))
        return None

    @retry_etcd()
    def save_health_status(self, entity_type: str, name: str, status_data: Dict) -> None:
        """Save the health status dictionary directly."""
        self.client.put(f"/health/{entity_type}/{name}", json.dumps(status_data))

    @retry_etcd()
    def get_user_usage(self, user_id: str) -> Dict[str, int]:
        """Retrieve token usage for a user."""
        value, _ = self.client.get(f"/usage/{user_id}")
        if value:
            return json.loads(value.decode('utf-8'))
        return {"input_tokens": 0, "output_tokens": 0, "total_requests": 0}

    def _atomic_update_usage_json(self, key: str, update_fn) -> Dict[str, Any]:
        """Atomically update a JSON record in etcd using Compare-And-Swap (CAS)."""
        for _ in range(20):
            raw_val, _ = self.client.get(key)
            if raw_val is None:
                initial_data = update_fn({})
                new_bytes = json.dumps(initial_data).encode('utf-8')
                if self.client.put_if_not_exists(key, new_bytes):
                    return initial_data
            else:
                try:
                    current_data = json.loads(raw_val.decode('utf-8'))
                except Exception:
                    current_data = {}
                updated_data = update_fn(current_data)
                new_bytes = json.dumps(updated_data).encode('utf-8')
                if self.client.replace(key, raw_val, new_bytes):
                    return updated_data
        # Fallback if max retries reached
        raw_val, _ = self.client.get(key)
        current_data = json.loads(raw_val.decode('utf-8')) if raw_val else {}
        final_data = update_fn(current_data)
        self.client.put(key, json.dumps(final_data))
        return final_data

    @retry_etcd()
    def record_usage(self, user_id: str, input_tokens: int, output_tokens: int) -> None:
        """Increment token usage for a user atomically."""
        if not user_id:
            return
            
        inp = input_tokens or 0
        outp = output_tokens or 0
        
        def update(current: Dict[str, Any]) -> Dict[str, Any]:
            current["input_tokens"] = current.get("input_tokens", 0) + inp
            current["output_tokens"] = current.get("output_tokens", 0) + outp
            current["total_requests"] = current.get("total_requests", 0) + 1
            return current

        self._atomic_update_usage_json(f"/usage/{user_id}", update)

    @retry_etcd()
    def get_user_agent_usage(self, user_id: str) -> Dict[str, Dict[str, int]]:
        """Retrieve token usage per agent for a user."""
        usage = {}
        prefix = f"/usage/{user_id}/agents/"
        for value, metadata in self.client.get_prefix(prefix):
            if value:
                agent_name = metadata.key.decode('utf-8')[len(prefix):]
                usage[agent_name] = json.loads(value.decode('utf-8'))
        return usage

    @retry_etcd()
    def record_agent_usage(self, user_id: str, agent_name: str, input_tokens: int, output_tokens: int) -> None:
        """Increment token usage for a specific agent for a user atomically."""
        if not user_id or not agent_name:
            return
            
        inp = input_tokens or 0
        outp = output_tokens or 0
        
        def update(current: Dict[str, Any]) -> Dict[str, Any]:
            if not current:
                current = {"input_tokens": 0, "output_tokens": 0, "total_requests": 0}
            current["input_tokens"] = current.get("input_tokens", 0) + inp
            current["output_tokens"] = current.get("output_tokens", 0) + outp
            current["total_requests"] = current.get("total_requests", 0) + 1
            return current

        self._atomic_update_usage_json(f"/usage/{user_id}/agents/{agent_name}", update)

    @retry_etcd()
    def get_user_tool_usage(self, user_id: str) -> Dict[str, int]:
        """Retrieve tool execution counts for a user."""
        usage = {}
        prefix = f"/usage/{user_id}/tools/"
        for value, metadata in self.client.get_prefix(prefix):
            if value:
                tool_name = metadata.key.decode('utf-8')[len(prefix):]
                usage[tool_name] = int(value.decode('utf-8'))
        return usage

    @retry_etcd()
    def record_tool_usage(self, user_id: str, tool_name: str) -> None:
        """Increment execution count for a specific tool for a user."""
        if not user_id or not tool_name:
            return
            
        key = f"/usage/{user_id}/tools/{tool_name}"
        value, _ = self.client.get(key)
        current = int(value.decode('utf-8')) if value else 0
        
        self.client.put(key, str(current + 1))

    @retry_etcd()
    def list_all_users(self) -> List[Dict]:
        """List all user profiles."""
        users = []
        for value, _ in self.client.get_prefix("/users/profiles/"):
            if value:
                try:
                    users.append(json.loads(value.decode('utf-8')))
                except Exception as e:
                    logger.warning(f"Failed to decode user record: {e}")
        return users

    @retry_etcd()
    def list_all_keys(self) -> List[Dict]:
        """List all API keys across the system."""
        keys = []
        
        for value, metadata in self.client.get_prefix("/keys_v2/"):
            if value:
                try:
                    data = json.loads(value.decode('utf-8'))
                    key_hash = metadata.key.decode('utf-8').split('/')[-1]
                    data["key_masked"] = data.get("key_preview", "***")
                    data["key_id"] = key_hash
                    keys.append(data)
                except Exception as e:
                    logger.warning(f"Failed to decode v2 key record: {e}")
        return keys

    def toggle_user_ban(self, user_id: str, is_banned: bool) -> None:
        """Toggle ban status for a user.

        Not itself @retry_etcd()-decorated: get_user()/upsert_user() already retry
        independently. Stacking a third retry layer on top of both multiplies worst-case
        retry time (10x(10+10) attempts, ~400+s) instead of adding to it -- see
        get_agent_memory_enabled above for the same pattern."""
        user = self.get_user(user_id)
        if user:
            user["is_banned"] = is_banned
            self.upsert_user(user_id, user)

    @retry_etcd()
    def get_all_agent_configs(self) -> Dict[str, Dict]:
        """Fetch all agent configurations in a single prefix call."""
        return self._get_all_configs_by_prefix("/registry/agents/")

    @retry_etcd()
    def get_all_agent_skills(self) -> Dict[str, str]:
        """Fetch all agent skills in a single prefix call."""
        skills = {}
        prefix = "/registry/agents/"
        for value, metadata in self.client.get_prefix(prefix):
            key_str = metadata.key.decode('utf-8')
            if key_str.startswith(prefix) and key_str.endswith("/skills") and value:
                rest = key_str[len(prefix):]
                name = rest.split('/')[0]
                if name:
                    skills[name] = value.decode('utf-8')
        return skills

    @retry_etcd()
    def get_all_health_statuses(self, entity_type: str) -> Dict[str, Dict]:
        """Fetch all health statuses for a given type in a single prefix call."""
        statuses = {}
        prefix = f"/health/{entity_type}/"
        for value, metadata in self.client.get_prefix(prefix):
            key_str = metadata.key.decode('utf-8')
            if key_str.startswith(prefix) and value:
                name = key_str[len(prefix):]
                try:
                    statuses[name] = json.loads(value.decode('utf-8'))
                except json.JSONDecodeError:
                    pass
        return statuses

    @retry_etcd()
    def record_agent_run_state(self, agent_name: str, run_id: str, state: str, metadata: Dict) -> bool:
        """Record or update the state of an agent execution run in etcd.

        Returns True if the state was written, False if blocked by terminal-state guard.
        """
        from datetime import datetime, timezone
        key = f"/runs/{agent_name}/{run_id}"
        record = {
            "run_id": run_id,
            "agent_name": agent_name,
            "state": state,  # pending, processing, completed, failed
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata
        }
        # To support updating existing records, fetch and merge if it already exists
        with self.client.lock(f"{key}_lock"):
            value, _ = self.client.get(key)
            if value:
                try:
                    existing = json.loads(value.decode('utf-8'))
                    # terminal states are immutable — no further transitions allowed
                    _TERMINAL = {"completed", "failed", "cancelled"}
                    if existing.get("state") in _TERMINAL:
                        return False
                    existing.update(record)
                    if "created_at" not in existing:
                        existing["created_at"] = existing.get("timestamp")
                    existing["updated_at"] = record["timestamp"]
                    record = existing
                except Exception:
                    pass
            else:
                record["created_at"] = record["timestamp"]
                record["updated_at"] = record["timestamp"]

            self.client.put(key, json.dumps(record))
            return True

    @retry_etcd()
    def get_agent_run(self, agent_name: str, run_id: str) -> Optional[Dict]:
        """Retrieve a specific run by agent name and run_id without scanning the full prefix."""
        key = f"/runs/{agent_name}/{run_id}"
        value, _ = self.client.get(key)
        if value:
            try:
                return json.loads(value.decode('utf-8'))
            except Exception as e:
                logger.warning(f"Failed to decode agent run record for {key}: {e}")
                return None
        return None

    @retry_etcd()
    def get_agent_runs(self, agent_name: str, limit: Optional[int] = None) -> List[Dict]:
        """Retrieve runs for a specific agent, sorted by timestamp descending, with optional limit."""
        runs = []
        prefix = f"/runs/{agent_name}/"
        for value, metadata in self.client.get_prefix(prefix):
            if value:
                try:
                    runs.append(json.loads(value.decode('utf-8')))
                except Exception as e:
                    logger.warning(f"Failed to decode agent run record: {e}")
        runs.sort(key=lambda x: x.get("updated_at", x.get("timestamp", "")), reverse=True)
        if limit is not None and limit > 0:
            return runs[:limit]
        return runs

    @retry_etcd()
    def prune_agent_runs(self, agent_name: str, keep_last: int = 50) -> int:
        """Prune historical runs for an agent, retaining only the latest `keep_last` records.
        
        Returns the number of deleted records.
        """
        prefix = f"/runs/{agent_name}/"
        records = []
        for value, metadata in self.client.get_prefix(prefix):
            key_str = metadata.key.decode('utf-8')
            if value:
                try:
                    parsed = json.loads(value.decode('utf-8'))
                    ts = parsed.get("updated_at", parsed.get("timestamp", ""))
                    records.append((key_str, ts))
                except Exception:
                    # If corrupted, mark for deletion
                    records.append((key_str, ""))
            else:
                records.append((key_str, ""))

        if len(records) <= keep_last:
            return 0

        # Sort descending by timestamp so newest records come first
        records.sort(key=lambda x: x[1], reverse=True)
        to_delete = records[keep_last:]
        deleted_count = 0
        for key_str, _ in to_delete:
            try:
                self.client.delete(key_str)
                deleted_count += 1
            except Exception as e:
                logger.warning(f"Failed to delete old run key {key_str}: {e}")
        
        logger.info(f"Pruned {deleted_count} historical run records for agent '{agent_name}'.")
        return deleted_count

    # --- MCP OAuth 2.1 State Management ---

    def get_or_create_jwt_secret(self) -> bytes:
        """Return the stable JWT signing secret, creating it on first call.

        The secret is stored encrypted in etcd at /config/oauth/jwt_secret.
        Concurrent calls are serialized via an etcd lock so only one secret
        is ever written.
        """
        key = "/config/oauth/jwt_secret"
        value, _ = self.client.get(key)
        if value:
            return _decrypt_string(value.decode("utf-8")).encode("utf-8")

        with self.client.lock("oauth_jwt_secret_init", ttl=10):
            # Re-check inside the lock to handle the concurrent-creation race
            value, _ = self.client.get(key)
            if value:
                return _decrypt_string(value.decode("utf-8")).encode("utf-8")

            new_secret = secrets.token_hex(32)
            self.client.put(key, _encrypt_string(new_secret))
            logger.info("Generated and stored new JWT signing secret.")
            return new_secret.encode("utf-8")

    @retry_etcd()
    def save_oauth_client(self, client_id: str, client_secret: str, metadata: Dict) -> None:
        """Register a dynamic OAuth client.

        The raw client_secret is never stored; only its SHA-256 hash is kept
        so it can be verified later without being leaked from etcd.
        """
        client_secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()
        record = {
            "client_id": client_id,
            "client_secret_hash": client_secret_hash,
            **metadata,
        }
        self.client.put(f"/oauth/clients/{client_id}", json.dumps(record))

    @retry_etcd()
    def get_oauth_client(self, client_id: str) -> Optional[Dict]:
        """Retrieve an OAuth client record by client_id."""
        value, _ = self.client.get(f"/oauth/clients/{client_id}")
        if value:
            return json.loads(value.decode("utf-8"))
        return None

    def save_oauth_code(self, code: str, data: Dict, ttl: int = 300) -> None:
        """Store a one-time authorization code with a TTL (default 5 min).

        The lease ensures etcd automatically purges the code after it expires,
        preventing stale codes from accumulating.
        """
        lease = self.client.lease(ttl)
        self.client.put(f"/oauth/codes/{code}", json.dumps(data), lease=lease)

    def get_and_delete_oauth_code(self, code: str) -> Optional[Dict]:
        """Atomically consume an authorization code (one-time use).

        Returns the code data if valid, None if not found or already used.
        Deletion happens inside a lock to prevent replay attacks under concurrent requests.
        """
        key = f"/oauth/codes/{code}"
        with self.client.lock(f"oauth_code_{code}", ttl=5):
            value, _ = self.client.get(key)
            if not value:
                return None
            data = json.loads(value.decode("utf-8"))
            self.client.delete(key)
            return data

    def save_revoked_token(self, jti: str, exp: int) -> None:
        """Add a JWT ID to the revocation denylist.

        Uses a lease so etcd auto-purges the entry when the token would have
        expired anyway — no unbounded growth of the denylist.
        Not decorated with @retry_etcd() because lease creation is not idempotent.
        """
        ttl = max(int(exp - time.time()), 1)
        lease = self.client.lease(ttl)
        self.client.put(f"/oauth/revoked/{jti}", b"1", lease=lease)

    @retry_etcd()
    def is_token_revoked(self, jti: str) -> bool:
        """Return True if the JWT ID is on the revocation denylist."""
        value, _ = self.client.get(f"/oauth/revoked/{jti}")
        return value is not None


_identity_manager: Optional[IdentityManager] = None

def get_identity_manager() -> IdentityManager:
    global _identity_manager
    if _identity_manager is None:
        _identity_manager = IdentityManager(
            host=os.getenv("ETCD_HOST", "127.0.0.1"),
            port=int(os.getenv("ETCD_PORT", 2379))
        )
    return _identity_manager


class AuthMiddleware:
    def __init__(self, app, identity_mgr: IdentityManager):
        self.app = app
        self.identity_mgr = identity_mgr
        import os
        self.dev_mode = os.getenv("DEV_MODE", "false").lower() == "true"

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
            
        try:
            path = scope.get("path", "")
            normalized_path = re.sub(r'/+', '/', path)
            
            protected_prefixes = ("/v1/", "/sse", "/messages", "/mcp")
            if any(normalized_path.startswith(prefix) for prefix in protected_prefixes):
                headers = dict(scope.get("headers", []))
                auth_header = headers.get(b"authorization", b"").decode("utf-8", errors="ignore")

                proto = headers.get(b"x-forwarded-proto", b"https").decode("utf-8", errors="ignore")
                host = headers.get(b"host", b"localhost").decode("utf-8", errors="ignore")
                resource_metadata_url = f"{proto}://{host}/.well-known/oauth-protected-resource"
                www_authenticate = f'Bearer realm="mcp", resource_metadata="{resource_metadata_url}"'.encode()

                if self.dev_mode and (not auth_header or not auth_header.startswith("Bearer ")):
                    auth_token_var.set(DEV_MODE_AUTH_TOKEN)
                    user_id_var.set("dev-user-id")
                    scope["state"] = scope.get("state", {})
                    scope["state"]["user_id"] = "dev-user-id"
                    return await self.app(scope, receive, send)
                
                if not auth_header or not auth_header.startswith("Bearer "):
                    await self._send_error(scope, send, 401, b'{"error": "Missing or invalid Authorization header"}', [(b"www-authenticate", www_authenticate)])
                    return
                
                token = auth_header.split(" ")[1]
                try:
                    if token.startswith("exec_"):
                        user_id = await asyncio.to_thread(self.identity_mgr.validate_execution_token, token)
                    elif token.count('.') == 2:
                        user_id = await self._validate_jwt(token)
                    else:
                        user_id = await asyncio.to_thread(self.identity_mgr.validate_key, token)
                except Exception as e:
                    logger.error(f"Error validating token: {e}")
                    user_id = None

                if not user_id:
                    await self._send_error(scope, send, 401, b'{"error": "Invalid or expired token"}', [(b"www-authenticate", www_authenticate)])
                    return
                    
                # Set the ContextVars so downstream async functions can access them
                auth_token_var.set(token)
                user_id_var.set(user_id)
                
                # Check if user is banned
                user = await asyncio.to_thread(self.identity_mgr.get_user, user_id)
                if user and user.get("is_banned"):
                    await self._send_error(scope, send, 403, b'{"error": "Account suspended"}')
                    return
                
                # Add user_id to scope state for framework compatibility
                scope["state"] = scope.get("state", {})
                scope["state"]["user_id"] = user_id
                
            return await self.app(scope, receive, send)
        except Exception as e:
            logger.error(f"Unhandled exception in ASGI AuthMiddleware: {e}", exc_info=True)
            await self._send_error(scope, send, 500, b'{"error": "Internal Server Error"}')

    async def _validate_jwt(self, token: str) -> Optional[str]:
        """Validate an MCP OAuth JWT and return the sub (user_id) if valid."""
        try:
            secret = await asyncio.to_thread(self.identity_mgr.get_or_create_jwt_secret)
            payload = jwt.decode(token, secret, algorithms=["HS256"], audience="mcp:tools")
            jti = payload.get("jti")
            if jti:
                revoked = await asyncio.to_thread(self.identity_mgr.is_token_revoked, jti)
                if revoked:
                    logger.warning("JWT rejected: token has been revoked (jti=%s)", jti)
                    return None
            return payload.get("sub")
        except jwt.PyJWTError as e:
            logger.warning(f"JWT validation failed: {e}")
            return None

    async def _send_error(self, scope, send, status: int, body: bytes, extra_headers: list = None):
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
        else:
            response_headers = [(b"content-type", b"application/json")]
            if extra_headers:
                response_headers.extend(extra_headers)
            await send({
                "type": "http.response.start",
                "status": status,
                "headers": response_headers,
            })
            await send({
                "type": "http.response.body",
                "body": body,
            })

def is_admin(request: Request) -> bool:
    """Helper to check if the current session user is an admin."""
    user = request.session.get('user')
    if not user:
        return False
        
    admin_users = [u.strip() for u in os.getenv("ADMIN_USERS", "").split(",") if u.strip()]
    return user.get("email") in admin_users

async def get_current_user(request: Request):
    """Helper to get the current user from the session, enforcing ban status."""
    user = request.session.get('user')
    if not user:
        return None
    user_id = user.get('sub')
    if user_id:
        from core.dependencies import identity_mgr
        db_user = await asyncio.to_thread(identity_mgr.get_user, user_id)
        if db_user and db_user.get('is_banned'):
            request.session.clear()
            return None
    return user
