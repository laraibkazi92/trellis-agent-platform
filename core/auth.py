import json
import secrets
from typing import Dict, List, Optional
import etcd3

class IdentityManager:
    def __init__(self, host: str = "127.0.0.1", port: int = 2379):
        self.client = etcd3.client(host=host, port=port)
    
    def upsert_user(self, user_id: str, profile: Dict) -> None:
        """Create or update a user profile."""
        self.client.put(f"/users/{user_id}", json.dumps(profile))
        
    def get_user(self, user_id: str) -> Optional[Dict]:
        """Retrieve a user profile."""
        value, metadata = self.client.get(f"/users/{user_id}")
        if value:
            return json.loads(value.decode('utf-8'))
        return None

    def create_key(self, user_id: str, key_name: str) -> str:
        """Create a new API key for a user."""
        api_key = f"tl_{secrets.token_urlsafe(32)}"
        key_data = {
            "user_id": user_id,
            "name": key_name,
            "key": api_key,
        }
        self.client.put(f"/keys/{api_key}", json.dumps(key_data))
        return api_key

    def list_keys(self, user_id: str) -> List[Dict]:
        """List all API keys for a user."""
        keys = []
        for value, metadata in self.client.get_prefix("/keys/"):
            data = json.loads(value.decode('utf-8'))
            if data.get("user_id") == user_id:
                keys.append(data)
        return keys

    def delete_key(self, api_key: str) -> bool:
        """Revoke an API key."""
        deleted = self.client.delete(f"/keys/{api_key}")
        return deleted

    def validate_key(self, api_key: str) -> Optional[str]:
        """Validate an API key and return the associated user_id if valid."""
        value, metadata = self.client.get(f"/keys/{api_key}")
        if value:
            data = json.loads(value.decode('utf-8'))
            return data.get("user_id")
        return None

from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, identity_mgr: IdentityManager):
        super().__init__(app)
        self.identity_mgr = identity_mgr

    async def dispatch(self, request: Request, call_next):
        # We only protect specific routes, typically /v1/chat/completions and /sse
        if request.url.path in ["/v1/chat/completions", "/sse"]:
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return JSONResponse({"error": "Missing or invalid Authorization header"}, status_code=401)
            
            token = auth_header.split(" ")[1]
            user_id = self.identity_mgr.validate_key(token)
            
            if not user_id:
                return JSONResponse({"error": "Invalid API Key"}, status_code=401)
                
            # Add user_id to request state
            request.state.user_id = user_id
            
        return await call_next(request)
