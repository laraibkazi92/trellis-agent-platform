import hmac
import hashlib
import json
import logging
from typing import Optional, Dict, Any, Callable
from fastapi import APIRouter, Request, HTTPException, Depends
from core.auth import IdentityManager
from .queue import EtcdQueue

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])
queue = EtcdQueue()

def get_identity_mgr():
    from core.host import identity_mgr
    return identity_mgr

def validate_github(payload_body: bytes, secret: str, request: Request) -> bool:
    signature_header = request.headers.get("X-Hub-Signature-256")
    if not signature_header:
        return False
    
    hash_object = hmac.new(secret.encode('utf-8'), msg=payload_body, digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()
    return hmac.compare_digest(expected_signature, signature_header)

def validate_issues(payload_body: bytes, secret: str, request: Request) -> bool:
    # Example Issues HMAC validation (often custom or just a token in query/header)
    # Issues usually uses x-hub-signature or standard HMAC. We will assume standard SHA-256.
    signature_header = request.headers.get("X-Hub-Signature")
    if not signature_header:
        # Fallback to Authorization Bearer or custom token if required
        return False
    hash_object = hmac.new(secret.encode('utf-8'), msg=payload_body, digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()
    return hmac.compare_digest(expected_signature, signature_header)

def validate_slack(payload_body: bytes, secret: str, request: Request) -> bool:
    slack_signature = request.headers.get("X-Slack-Signature")
    slack_request_timestamp = request.headers.get("X-Slack-Request-Timestamp")
    
    if not slack_signature or not slack_request_timestamp:
        return False
        
    basestring = f"v0:{slack_request_timestamp}:{payload_body.decode('utf-8')}"
    my_signature = 'v0=' + hmac.new(secret.encode('utf-8'), basestring.encode('utf-8'), hashlib.sha256).hexdigest()
    return hmac.compare_digest(my_signature, slack_signature)

def validate_notion(payload_body: bytes, secret: str, request: Request) -> bool:
    # Placeholder for Notion. Let's assume generic SHA-256 HMAC for webhooks if they use one.
    return validate_generic(payload_body, secret, request)

def validate_support(payload_body: bytes, secret: str, request: Request) -> bool:
    # Support sends X-Support-Signature
    signature = request.headers.get("X-Support-Signature")
    if not signature:
        return False
    hash_object = hmac.new(secret.encode('utf-8'), msg=payload_body, digestmod=hashlib.sha256)
    expected_signature = hash_object.hexdigest()
    return hmac.compare_digest(expected_signature, signature)

def validate_generic(payload_body: bytes, secret: str, request: Request) -> bool:
    # Generic SHA-256 signature in Authorization or X-Signature header
    signature = request.headers.get("X-Signature") or request.headers.get("Authorization")
    if not signature:
        return False
    hash_object = hmac.new(secret.encode('utf-8'), msg=payload_body, digestmod=hashlib.sha256)
    expected_signature = hash_object.hexdigest()
    # Strip prefix if it exists in Authorization header (e.g. Bearer )
    if signature.startswith("Bearer "):
        signature = signature[7:]
    elif signature.startswith("sha256="):
        expected_signature = "sha256=" + expected_signature
        
    return hmac.compare_digest(expected_signature, signature)

VALIDATORS: Dict[str, Callable] = {
    "github": validate_github,
    "issues": validate_issues,
    "slack": validate_slack,
    "notion": validate_notion,
    "support": validate_support,
    "generic": validate_generic
}

@router.post("/{agent_name}")
async def receive_webhook(agent_name: str, request: Request):
    identity_mgr = get_identity_mgr()
    import asyncio
    config_data = await asyncio.to_thread(identity_mgr.get_agent_config, agent_name)
    
    if not config_data or config_data.get("type") != "background":
        raise HTTPException(status_code=404, detail="Background agent not found")
        
    trigger = config_data.get("trigger")
    if not trigger or trigger.get("type") != "webhook":
        raise HTTPException(status_code=400, detail="Agent is not configured for webhooks")
        
    provider = trigger.get("provider", "generic")
    secret_key = trigger.get("secret")
    
    if not secret_key:
        raise HTTPException(status_code=500, detail="Webhook secret not configured for agent")
        
    # Secret Management: allow environment variable resolution
    import os
    actual_secret = secret_key
    if secret_key.startswith("env:"):
        env_var = secret_key[4:]
        actual_secret = os.environ.get(env_var)
    elif secret_key.startswith("secret:"):
        # Placeholder for identity_mgr secure secret store resolution
        # actual_secret = identity_mgr.get_secret(secret_key[7:])
        pass
        
    if not actual_secret:
        raise HTTPException(status_code=500, detail="Webhook secret could not be resolved from environment")
    
    payload_bytes = await request.body()
    
    validator = VALIDATORS.get(provider, validate_generic)
    if not validator(payload_bytes, actual_secret, request):
        raise HTTPException(status_code=401, detail="Invalid signature")
        
    try:
        # Wrap payload in XML tags
        try:
            payload_str = payload_bytes.decode('utf-8')
        except UnicodeDecodeError:
            payload_str = "Invalid UTF-8 payload received"

        try:
            # Format nicely if it's JSON
            json_obj = json.loads(payload_str)
            payload_str = json.dumps(json_obj, indent=2)
        except json.JSONDecodeError:
            pass
            
        xml_payload = f"<event_payload>\n{payload_str}\n</event_payload>"
        
        task_payload = {
            "agent_name": agent_name,
            "trigger_type": "webhook",
            "provider": provider,
            "prompt": xml_payload
        }
        
        task_id = queue.push(task_payload)
        return {"status": "accepted", "task_id": task_id}
        
    except Exception as e:
        logger.error(f"Error processing webhook: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
