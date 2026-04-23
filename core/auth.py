import json
import secrets
import logging
import time
import re
import contextvars
import asyncio
from typing import Dict, List, Optional, Any
from functools import wraps

import etcd3
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

auth_token_var = contextvars.ContextVar("auth_token", default=None)
user_id_var = contextvars.ContextVar("user_id", default=None)

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
        self.client.put(f"/users/{user_id}", json.dumps(profile))
        
    @retry_etcd()
    def get_user(self, user_id: str) -> Optional[Dict]:
        """Retrieve a user profile."""
        value, metadata = self.client.get(f"/users/{user_id}")
        if value:
            return json.loads(value.decode('utf-8'))
        return None

    @retry_etcd()
    def get_user_secrets(self, user_id: str) -> Dict[str, str]:
        """Retrieve user-specific secrets."""
        value, _ = self.client.get(f"/users/{user_id}/secrets")
        if value:
            return json.loads(value.decode('utf-8'))
        return {}

    @retry_etcd()
    def save_user_secrets(self, user_id: str, secrets_data: Dict[str, str]) -> None:
        """Save user-specific secrets."""
        self.client.put(f"/users/{user_id}/secrets", json.dumps(secrets_data))

    @retry_etcd()
    def create_key(self, user_id: str, key_name: str) -> str:
        """Create a new API key for a user."""
        api_key = f"tl_{secrets.token_urlsafe(32)}"
        key_data = {
            "user_id": user_id,
            "name": key_name,
            "key": api_key,
        }
        self.client.put(f"/keys/{api_key}", json.dumps(key_data))
        # Maintain a secondary index for fast retrieval by user
        self.client.put(f"/user_keys/{user_id}/{api_key}", "1")
        return api_key

    @retry_etcd()
    def list_keys(self, user_id: str) -> List[Dict]:
        """List all API keys for a user efficiently using secondary index."""
        keys = []
        for value, metadata in self.client.get_prefix(f"/user_keys/{user_id}/"):
            # metadata.key is like b'/user_keys/{user_id}/{api_key}'
            key_path = metadata.key.decode('utf-8')
            api_key = key_path.split('/')[-1]
            
            # Retrieve actual key data
            key_data_raw, _ = self.client.get(f"/keys/{api_key}")
            if key_data_raw:
                data = json.loads(key_data_raw.decode('utf-8'))
                # Mask the key to prevent HTML source leaks
                raw_key = data.get("key", "")
                if raw_key.startswith("tl_") and len(raw_key) > 8:
                    data["key_masked"] = raw_key[:6] + "..." + raw_key[-4:]
                else:
                    data["key_masked"] = "***"
                keys.append(data)
        return keys

    @retry_etcd()
    def delete_key(self, api_key: str) -> bool:
        """Revoke an API key."""
        # First retrieve the key to find the user_id
        value, _ = self.client.get(f"/keys/{api_key}")
        if value:
            data = json.loads(value.decode('utf-8'))
            user_id = data.get("user_id")
            if user_id:
                self.client.delete(f"/user_keys/{user_id}/{api_key}")
        
        deleted = self.client.delete(f"/keys/{api_key}")
        return deleted

    @retry_etcd()
    def validate_key(self, api_key: str) -> Optional[str]:
        """Validate an API key and return the associated user_id if valid."""
        value, metadata = self.client.get(f"/keys/{api_key}")
        if value:
            data = json.loads(value.decode('utf-8'))
            return data.get("user_id")
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

class AuthMiddleware:
    def __init__(self, app, identity_mgr: IdentityManager):
        self.app = app
        self.identity_mgr = identity_mgr

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
            
        path = scope.get("path", "")
        normalized_path = re.sub(r'/+', '/', path)
        
        import os
        DEV_MODE = os.getenv("DEV_MODE", "false").lower() == "true"
        
        protected_prefixes = ("/v1/chat/completions", "/sse", "/messages", "/mcp")
        if any(normalized_path.startswith(prefix) for prefix in protected_prefixes):
            headers = dict(scope.get("headers", []))
            auth_header = headers.get(b"authorization", b"").decode("utf-8", errors="ignore")
            
            if DEV_MODE and (not auth_header or not auth_header.startswith("Bearer ")):
                auth_token_var.set("dev-token")
                user_id_var.set("dev-user-id")
                scope["state"] = scope.get("state", {})
                scope["state"]["user_id"] = "dev-user-id"
                return await self.app(scope, receive, send)
                
            if not auth_header or not auth_header.startswith("Bearer "):
                await self._send_response(send, 401, b'{"error": "Missing or invalid Authorization header"}')
                return
            
            token = auth_header.split(" ")[1]
            try:
                user_id = await asyncio.to_thread(self.identity_mgr.validate_key, token)
            except Exception as e:
                logger.error(f"Error validating key: {e}")
                user_id = None
            
            if not user_id:
                if DEV_MODE:
                    auth_token_var.set("dev-token")
                    user_id_var.set("dev-user-id")
                    scope["state"] = scope.get("state", {})
                    scope["state"]["user_id"] = "dev-user-id"
                    return await self.app(scope, receive, send)
                await self._send_response(send, 401, b'{"error": "Invalid API Key"}')
                return
                
            # Set the ContextVars so downstream async functions can access them
            auth_token_var.set(token)
            user_id_var.set(user_id)
            
            # Add user_id to scope state for framework compatibility
            scope["state"] = scope.get("state", {})
            scope["state"]["user_id"] = user_id
            
        return await self.app(scope, receive, send)

    async def _send_response(self, send, status: int, body: bytes):
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json")],
        })
        await send({
            "type": "http.response.body",
            "body": body,
        })
