import json
import secrets
import logging
import time
import re
import contextvars
import asyncio
import hashlib
import os
from typing import Dict, List, Optional, Any
from functools import wraps

import etcd3
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
    try:
        from cryptography.fernet import Fernet
        f = Fernet(_get_encryption_key())
        return f.encrypt(plaintext.encode('utf-8')).decode('utf-8')
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        return plaintext

def _decrypt_string(ciphertext: str) -> str:
    if not ciphertext:
        return ciphertext
    try:
        from cryptography.fernet import Fernet
        f = Fernet(_get_encryption_key())
        return f.decrypt(ciphertext.encode('utf-8')).decode('utf-8')
    except Exception:
        # Fallback if the string was not encrypted or key is wrong
        return ciphertext

def retry_etcd(max_retries=10, delay=2):
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(self, *args, **kwargs)
                except Exception as e:
                    logger.warning(f"etcd operation failed (attempt {attempt + 1}/{max_retries}): {e}")
                    if attempt == max_retries - 1:
                        logger.error(f"etcd operation failed after {max_retries} attempts.")
                        raise
                    time.sleep(delay)
        return wrapper
    return decorator

class IdentityManager:
    def __init__(self, host: str = "127.0.0.1", port: int = 2379):
        self.client = etcd3.client(host=host, port=port)
    
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
    def get_user_secrets(self, user_id: str) -> Dict[str, str]:
        """Retrieve user-specific secrets."""
        value, _ = self.client.get(f"/users/secrets/{user_id}")
        if value:
            decoded = value.decode('utf-8')
            decrypted = _decrypt_string(decoded)
            try:
                return json.loads(decrypted)
            except Exception as e:
                logger.error(f"Failed to parse user secrets JSON: {e}")
                return {}
        return {}

    @retry_etcd()
    def save_user_secrets(self, user_id: str, secrets_data: Dict[str, str]) -> None:
        """Save user-specific secrets securely using encryption."""
        serialized = json.dumps(secrets_data)
        encrypted = _encrypt_string(serialized)
        self.client.put(f"/users/secrets/{user_id}", encrypted)

    @retry_etcd()
    def get_global_secrets(self) -> Dict[str, str]:
        """Retrieve system-wide global secrets."""
        value, _ = self.client.get("/config/framework/global_secrets")
        if value:
            decoded = value.decode('utf-8')
            decrypted = _decrypt_string(decoded)
            try:
                return json.loads(decrypted)
            except Exception as e:
                logger.error(f"Failed to parse global secrets JSON: {e}")
                return {}
        return {}

    @retry_etcd()
    def save_global_secrets(self, secrets_data: Dict[str, str]) -> None:
        """Save system-wide global secrets securely using encryption."""
        serialized = json.dumps(secrets_data)
        encrypted = _encrypt_string(serialized)
        self.client.put("/config/framework/global_secrets", encrypted)

    def get_resolved_secrets(self, user_id: str) -> Dict[str, str]:
        """Retrieve user secrets merged with global secrets (global takes precedence)."""
        user_secrets = self.get_user_secrets(user_id)
        global_secrets = self.get_global_secrets()
        return {**user_secrets, **global_secrets}

    @retry_etcd()
    def get_user_variables(self, user_id: str) -> Dict[str, str]:
        """Retrieve user-specific non-sensitive configuration variables."""
        value, _ = self.client.get(f"/users/variables/{user_id}")
        if value:
            try:
                return json.loads(value.decode('utf-8'))
            except Exception as e:
                logger.error(f"Failed to parse user variables JSON: {e}")
                return {}
        return {}

    @retry_etcd()
    def save_user_variables(self, user_id: str, variables_data: Dict[str, str]) -> None:
        """Save user-specific non-sensitive configuration variables."""
        self.client.put(f"/users/variables/{user_id}", json.dumps(variables_data))

    @retry_etcd()
    def get_global_variables(self) -> Dict[str, str]:
        """Retrieve system-wide global non-sensitive configuration variables."""
        value, _ = self.client.get("/config/framework/global_variables")
        if value:
            try:
                return json.loads(value.decode('utf-8'))
            except Exception as e:
                logger.error(f"Failed to parse global variables JSON: {e}")
                return {}
        return {}

    @retry_etcd()
    def save_global_variables(self, variables_data: Dict[str, str]) -> None:
        """Save system-wide global non-sensitive configuration variables."""
        self.client.put("/config/framework/global_variables", json.dumps(variables_data))

    def get_resolved_variables(self, user_id: str) -> Dict[str, str]:
        """Retrieve user variables merged with global variables (global takes precedence)."""
        user_variables = self.get_user_variables(user_id)
        global_variables = self.get_global_variables()
        return {**user_variables, **global_variables}

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
        """Retrieve the list of disabled agents."""
        disabled = self.get_config("disabled_agents", [])
        return disabled

    @retry_etcd()
    def set_disabled_agents(self, agents: List[str]) -> None:
        """Set the list of disabled agents."""
        self.set_config("disabled_agents", agents)

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

    @retry_etcd()
    def record_usage(self, user_id: str, input_tokens: int, output_tokens: int) -> None:
        """Increment token usage for a user."""
        if not user_id:
            return
            
        current = self.get_user_usage(user_id)
        current["input_tokens"] = current.get("input_tokens", 0) + input_tokens
        current["output_tokens"] = current.get("output_tokens", 0) + output_tokens
        current["total_requests"] = current.get("total_requests", 0) + 1
        
        self.client.put(f"/usage/{user_id}", json.dumps(current))

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
        """Increment token usage for a specific agent for a user."""
        if not user_id or not agent_name:
            return
            
        key = f"/usage/{user_id}/agents/{agent_name}"
        value, _ = self.client.get(key)
        current = json.loads(value.decode('utf-8')) if value else {"input_tokens": 0, "output_tokens": 0, "total_requests": 0}
        
        current["input_tokens"] += input_tokens
        current["output_tokens"] += output_tokens
        current["total_requests"] += 1
        
        self.client.put(key, json.dumps(current))

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
    def record_agent_run_state(self, agent_name: str, run_id: str, state: str, metadata: Dict) -> None:
        """Record or update the state of an agent execution run in etcd."""
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
        value, _ = self.client.get(key)
        if value:
            try:
                existing = json.loads(value.decode('utf-8'))
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

    @retry_etcd()
    def get_agent_runs(self, agent_name: str) -> List[Dict]:
        """Retrieve all runs for a specific agent, sorted by timestamp descending."""
        runs = []
        prefix = f"/runs/{agent_name}/"
        for value, metadata in self.client.get_prefix(prefix):
            if value:
                try:
                    runs.append(json.loads(value.decode('utf-8')))
                except Exception as e:
                    logger.warning(f"Failed to decode agent run record: {e}")
        runs.sort(key=lambda x: x.get("updated_at", x.get("timestamp", "")), reverse=True)
        return runs

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
            
            protected_prefixes = ("/v1/chat/completions", "/sse", "/messages", "/mcp")
            if any(normalized_path.startswith(prefix) for prefix in protected_prefixes):
                headers = dict(scope.get("headers", []))
                auth_header = headers.get(b"authorization", b"").decode("utf-8", errors="ignore")
                
                if self.dev_mode and (not auth_header or not auth_header.startswith("Bearer ")):
                    auth_token_var.set("dev-token")
                    user_id_var.set("dev-user-id")
                    scope["state"] = scope.get("state", {})
                    scope["state"]["user_id"] = "dev-user-id"
                    return await self.app(scope, receive, send)
                
                if not auth_header or not auth_header.startswith("Bearer "):
                    await self._send_error(scope, send, 401, b'{"error": "Missing or invalid Authorization header"}')
                    return
                
                token = auth_header.split(" ")[1]
                try:
                    if token.startswith("exec_"):
                        user_id = await asyncio.to_thread(self.identity_mgr.validate_execution_token, token)
                    else:
                        user_id = await asyncio.to_thread(self.identity_mgr.validate_key, token)
                except Exception as e:
                    logger.error(f"Error validating key or token: {e}")
                    user_id = None
                
                if not user_id:
                    if self.dev_mode:
                        auth_token_var.set("dev-token")
                        user_id_var.set("dev-user-id")
                        scope["state"] = scope.get("state", {})
                        scope["state"]["user_id"] = "dev-user-id"
                        return await self.app(scope, receive, send)
                    await self._send_error(scope, send, 401, b'{"error": "Invalid API Key"}')
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

    async def _send_error(self, scope, send, status: int, body: bytes):
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
        else:
            await send({
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"application/json")],
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
    """Helper to get the current user from the session."""
    return request.session.get('user')
