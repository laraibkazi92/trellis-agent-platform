import json
import secrets
import logging
import time
import re
import contextvars
import asyncio
from typing import Dict, List, Optional
from functools import wraps

import etcd3
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

auth_token_var = contextvars.ContextVar("auth_token", default=None)

def retry_etcd(max_retries=3, delay=1):
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

class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, identity_mgr: IdentityManager):
        super().__init__(app)
        self.identity_mgr = identity_mgr

    async def dispatch(self, request: Request, call_next):
        # Normalize the path to prevent bypasses like //v1/chat/completions
        normalized_path = re.sub(r'/+', '/', request.url.path)
        
        protected_prefixes = ("/v1/chat/completions", "/sse", "/messages", "/mcp")
        if any(normalized_path.startswith(prefix) for prefix in protected_prefixes):
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return JSONResponse({"error": "Missing or invalid Authorization header"}, status_code=401)
            
            token = auth_header.split(" ")[1]
            user_id = await asyncio.to_thread(self.identity_mgr.validate_key, token)
            
            if not user_id:
                return JSONResponse({"error": "Invalid API Key"}, status_code=401)
                
            # Add user_id to request state
            request.state.user_id = user_id
            # Set the ContextVar so downstream async functions (like gateway tools) can access it
            auth_token_var.set(token)
            
        return await call_next(request)
