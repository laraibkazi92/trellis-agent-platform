import json
import secrets
import logging
import time
import re
import contextvars
import asyncio
import hashlib
import jwt
import os
from typing import Dict, List, Optional, Any, Union
from functools import wraps
import warnings

from core.models import Identity, IdentityType

import pyetcd
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

auth_token_var = contextvars.ContextVar("auth_token", default=None)
user_id_var = contextvars.ContextVar("user_id", default=None)

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

def retry_etcd(max_retries=10, delay=2):
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(self, *args, **kwargs)
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
        Enterprise-grade config resolver.
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

    def get_user_secrets(self, user_id: str) -> Dict[str, str]:
        """Retrieve user-specific secrets. @deprecated: Use get_identity_config"""
        warnings.warn("get_user_secrets is deprecated, use get_identity_config", DeprecationWarning, stacklevel=2)
        return self._get_kv(f"/users/secrets/{user_id}", decrypt=True) or {}

    def save_user_secrets(self, user_id: str, secrets_data: Dict[str, str]) -> None:
        """Save user-specific secrets securely using encryption. @deprecated: Use save_identity_config"""
        warnings.warn("save_user_secrets is deprecated, use save_identity_config", DeprecationWarning, stacklevel=2)
        self._set_kv(f"/users/secrets/{user_id}", secrets_data, encrypt=True)

    def get_global_secrets(self) -> Dict[str, str]:
        """Retrieve system-wide global secrets. @deprecated: Use get_identity_config"""
        warnings.warn("get_global_secrets is deprecated, use get_identity_config", DeprecationWarning, stacklevel=2)
        return self._get_kv("/config/framework/global_secrets", decrypt=True) or {}

    def save_global_secrets(self, secrets_data: Dict[str, str]) -> None:
        """Save system-wide global secrets securely using encryption. @deprecated: Use save_identity_config"""
        warnings.warn("save_global_secrets is deprecated, use save_identity_config", DeprecationWarning, stacklevel=2)
        self._set_kv("/config/framework/global_secrets", secrets_data, encrypt=True)

    def get_resolved_secrets(self, user_id: str) -> Dict[str, str]:
        """Retrieve user secrets merged with global secrets (user takes precedence). @deprecated: Use get_resolved_config"""
        warnings.warn("get_resolved_secrets is deprecated, use get_resolved_config", DeprecationWarning, stacklevel=2)
        user_secrets = self.get_user_secrets(user_id)
        global_secrets = self.get_global_secrets()
        return {**global_secrets, **user_secrets}

    def get_user_variables(self, user_id: str) -> Dict[str, str]:
        """Retrieve user-specific non-sensitive configuration variables. @deprecated: Use get_identity_config"""
        warnings.warn("get_user_variables is deprecated, use get_identity_config", DeprecationWarning, stacklevel=2)
        return self._get_kv(f"/users/variables/{user_id}") or {}

    def save_user_variables(self, user_id: str, variables_data: Dict[str, str]) -> None:
        """Save user-specific non-sensitive configuration variables. @deprecated: Use save_identity_config"""
        warnings.warn("save_user_variables is deprecated, use save_identity_config", DeprecationWarning, stacklevel=2)
        self._set_kv(f"/users/variables/{user_id}", variables_data)

    def get_global_variables(self) -> Dict[str, str]:
        """Retrieve system-wide global non-sensitive configuration variables. @deprecated: Use get_identity_config"""
        warnings.warn("get_global_variables is deprecated, use get_identity_config", DeprecationWarning, stacklevel=2)
        return self._get_kv("/config/framework/global_variables") or {}

    def save_global_variables(self, variables_data: Dict[str, str]) -> None:
        """Save system-wide global non-sensitive configuration variables. @deprecated: Use save_identity_config"""
        warnings.warn("save_global_variables is deprecated, use save_identity_config", DeprecationWarning, stacklevel=2)
        self._set_kv("/config/framework/global_variables", variables_data)

    def get_resolved_variables(self, user_id: str) -> Dict[str, str]:
        """Retrieve user variables merged with global variables (user takes precedence). @deprecated: Use get_resolved_config"""
        warnings.warn("get_resolved_variables is deprecated, use get_resolved_config", DeprecationWarning, stacklevel=2)
        user_variables = self.get_user_variables(user_id)
        global_variables = self.get_global_variables()
        return {**global_variables, **user_variables}

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

    @retry_etcd()
    def get_disabled_agents(self) -> List[str]:
        """Retrieve the list of disabled agents (Legacy: maps to standard agents)."""
        return self.get_disabled_standard_agents()

    @retry_etcd()
    def set_disabled_agents(self, agents: List[str]) -> None:
        """Set the list of disabled agents (Legacy: maps to standard agents)."""
        self.set_disabled_standard_agents(agents)

    @retry_etcd()
    def get_disabled_standard_agents(self) -> List[str]:
        """Retrieve the list of disabled standard agents."""
        return self.get_config("disabled_standard_agents", [])

    @retry_etcd()
    def set_disabled_standard_agents(self, agents: List[str]) -> None:
        """Set the list of disabled standard agents."""
        self.set_config("disabled_standard_agents", agents)

    @retry_etcd()
    def get_disabled_workflows(self) -> List[str]:
        """Retrieve the list of disabled workflows."""
        return self.get_config("disabled_workflows", [])

    @retry_etcd()
    def set_disabled_workflows(self, workflows: List[str]) -> None:
        """Set the list of disabled workflows."""
        self.set_config("disabled_workflows", workflows)

    @retry_etcd()
    def get_agent_memory_enabled(self) -> bool:
        """Retrieve the global agent-memory feature flag (admin master switch)."""
        return bool(self.get_config("agent_memory_enabled", False))

    @retry_etcd()
    def set_agent_memory_enabled(self, enabled: bool) -> None:
        """Set the global agent-memory feature flag (admin master switch)."""
        self.set_config("agent_memory_enabled", bool(enabled))

    def get_rules_evaluation_timeout(self) -> Optional[float]:
        """Retrieve the admin-configured Trellis Rules Engine LLM evaluation timeout
        (seconds), or None if never set -- callers fall back to the
        RULES_EVALUATION_TIMEOUT env var default in that case.

        Not itself @retry_etcd()-decorated: get_config() already retries. Stacking a
        second retry layer on top of it multiplies worst-case retry time (10x10 attempts)
        instead of adding to it -- see get_agent_memory_enabled/set_agent_memory_enabled
        above for the same (pre-existing) pattern; not fixed here to keep this change
        scoped to the Rules Engine."""
        value = self.get_config("rules_evaluation_timeout", None)
        return float(value) if value is not None else None

    def set_rules_evaluation_timeout(self, timeout_seconds: float) -> None:
        """Set the admin-configured Trellis Rules Engine LLM evaluation timeout (seconds).

        Not itself @retry_etcd()-decorated -- see get_rules_evaluation_timeout above."""
        self.set_config("rules_evaluation_timeout", float(timeout_seconds))

    @retry_etcd()
    def clear_rules_evaluation_timeout(self) -> None:
        """Remove the admin override, reverting to the RULES_EVALUATION_TIMEOUT env var default."""
        self.client.delete("/config/framework/rules_evaluation_timeout")

    @retry_etcd()
    def get_app_config(self) -> Dict[str, Any]:
        """Retrieve the application configuration for whitelabeling."""
        # Start with environment variables as defaults
        config = {
            "APP_NAME": os.getenv("APP_NAME", "Trellis"),
            "APP_LOGO_URL": os.getenv("APP_LOGO_URL", ""),
            "APP_FAVICON_URL": os.getenv("APP_FAVICON_URL", ""),
            "APP_ACCENT_COLOR": os.getenv("APP_ACCENT_COLOR", "#0055FF"),
            "APP_ACCENT_COLOR_DARK": os.getenv("APP_ACCENT_COLOR_DARK", "#3377FF"),
        }
        
        # Try to override with etcd values if they exist
        for key in config.keys():
            etcd_val = self.get_config(f"app_{key.lower()}")
            if etcd_val:
                config[key] = etcd_val
                
        return config

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

    @retry_etcd()
    def get_all_agent_embeddings(self) -> Dict[str, List[float]]:
        """Bulk-fetch every agent's cached embedding vector, keyed by agent name."""
        embeddings: Dict[str, List[float]] = {}
        prefix = "/registry/agents/"
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

    @retry_etcd()
    def list_agents(self) -> List[str]:
        """List all agent names in the registry."""
        names = set()
        prefix = "/registry/agents/"
        for value, metadata in self.client.get_prefix(prefix):
            key_str = metadata.key.decode('utf-8')
            if key_str.startswith(prefix):
                # Extract the name part after the prefix
                rest = key_str[len(prefix):]
                name = rest.split('/')[0]
                if name:
                    names.add(name)
        return list(names)

    @retry_etcd()
    def save_tool_config(self, name: str, config: Dict) -> None:
        self.client.put(f"/registry/tools/{name}/config", json.dumps(config))

    @retry_etcd()
    def get_tool_config(self, name: str) -> Optional[Dict]:
        value, _ = self.client.get(f"/registry/tools/{name}/config")
        if value:
            return json.loads(value.decode('utf-8'))
        return None

    @retry_etcd()
    def list_tools(self) -> List[str]:
        """List all tool names in the registry."""
        names = set()
        prefix = "/registry/tools/"
        for value, metadata in self.client.get_prefix(prefix):
            key_str = metadata.key.decode('utf-8')
            if key_str.startswith(prefix):
                # Extract the name part after the prefix
                rest = key_str[len(prefix):]
                name = rest.split('/')[0]
                if name:
                    names.add(name)
        return list(names)

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
        embeddings: Dict[str, List[float]] = {}
        prefix = "/registry/tools/"
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

    @retry_etcd()
    def save_mcp_config(self, name: str, config: Dict) -> None:
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
        names = set()
        prefix = "/registry/mcps/"
        for value, metadata in self.client.get_prefix(prefix):
            key_str = metadata.key.decode('utf-8')
            if key_str.startswith(prefix):
                rest = key_str[len(prefix):]
                name = rest.split('/')[0]
                if name:
                    names.add(name)
        return list(names)

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

    @retry_etcd()
    def toggle_user_ban(self, user_id: str, is_banned: bool) -> None:
        """Toggle ban status for a user."""
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
                    auth_token_var.set("dev-token")
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

def get_identity_mgr():
    """Helper to get the global IdentityManager instance."""
    from core.dependencies import identity_mgr
    return identity_mgr

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
