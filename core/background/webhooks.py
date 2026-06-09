import hmac
import hashlib
import json
import logging
from typing import Optional, Dict, Any, Callable
from fastapi import APIRouter, Request, HTTPException, Depends
from core.auth import IdentityManager
from core.tasks import run_background_agent

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])

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
    signature_header = request.headers.get("X-Hub-Signature")
    if not signature_header:
        return False
    
    hash_object = hmac.new(secret.encode('utf-8'), msg=payload_body, digestmod=hashlib.sha256)
    expected_signature = hash_object.hexdigest()
    
    # Issues sometimes includes the sha256= prefix and sometimes doesn't depending on the integration type
    if signature_header.startswith("sha256="):
        expected_signature = "sha256=" + expected_signature
        
    return hmac.compare_digest(expected_signature, signature_header)

def validate_notion(payload_body: bytes, secret: str, request: Request) -> bool:
    # Notion signature validation (commonly uses Notion-Signature header)
    signature = request.headers.get("Notion-Signature")
    if not signature:
        # Fallback for third-party Notion webhook services
        return validate_generic(payload_body, secret, request)
        
    hash_object = hmac.new(secret.encode('utf-8'), msg=payload_body, digestmod=hashlib.sha256)
    expected_signature = hash_object.hexdigest()
    return hmac.compare_digest(expected_signature, signature)

def validate_support(payload_body: bytes, secret: str, request: Request) -> bool:
    # Support does not natively support dynamic HMAC signing of webhook payloads.
    # Instead, we validate via static token validation using the "Authorization: Bearer <token>"
    # header (as configured in Support automation headers) or custom "X-Support-Signature".
    token_header = request.headers.get("Authorization") or request.headers.get("X-Support-Signature")
    if not token_header:
        return False
        
    # Strip prefix if it exists in Authorization header (e.g. "Bearer ")
    provided_token = token_header[7:] if token_header.startswith("Bearer ") else token_header
    expected_token = secret[7:] if secret.startswith("Bearer ") else secret
    
    # Use compare_digest for secure constant-time comparison
    return hmac.compare_digest(provided_token, expected_token)

def validate_generic(payload_body: bytes, secret: str, request: Request) -> bool:
    # Generic SHA-256 signature or static token in Authorization or X-Signature header
    signature_header = request.headers.get("X-Signature") or request.headers.get("Authorization")
    if not signature_header:
        return False
        
    # Clean the signature/token prefix if it exists (e.g. Bearer )
    provided_token = signature_header[7:] if signature_header.startswith("Bearer ") else signature_header
    
    # 1. Try dynamic HMAC validation first for backwards compatibility
    hash_object = hmac.new(secret.encode('utf-8'), msg=payload_body, digestmod=hashlib.sha256)
    expected_hmac = hash_object.hexdigest()
    
    # Handle optional "sha256=" prefix if provider sends it
    cmp_token = provided_token[7:] if provided_token.startswith("sha256=") else provided_token
    
    if hmac.compare_digest(cmp_token, expected_hmac):
        return True
        
    # 2. Fall back to simple static token comparison for non-HMAC providers like Support
    expected_token = secret[7:] if secret.startswith("Bearer ") else secret
    return hmac.compare_digest(provided_token, expected_token)

def validate_slack(payload_body: bytes, secret: str, request: Request) -> bool:
    signature = request.headers.get("X-Slack-Signature")
    timestamp = request.headers.get("X-Slack-Request-Timestamp")
    if not signature or not timestamp:
        return False
    
    # Slack signature requires concatenating version, timestamp, and body
    sig_basestring = f"v0:{timestamp}:{payload_body.decode('utf-8')}".encode('utf-8')
    hash_object = hmac.new(secret.encode('utf-8'), msg=sig_basestring, digestmod=hashlib.sha256)
    expected_signature = f"v0={hash_object.hexdigest()}"
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
    
    if not config_data or config_data.get("type") not in ("background_agent", "background_script"):
        raise HTTPException(status_code=404, detail="Background agent not found")
        
    disabled_workflows = identity_mgr.get_disabled_workflows()
    if agent_name in disabled_workflows:
        raise HTTPException(status_code=403, detail="Workflow disabled by admin")
        
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
        actual_secret = await asyncio.to_thread(identity_mgr.get_config, f"secrets/{secret_key[7:]}")
        
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

        # Sanitize by replacing CDATA end tags to prevent breakout
        payload_str = payload_str.replace("]]>", "]]]]><![CDATA[>")
        xml_payload = f"<event_payload><![CDATA[\n{payload_str}\n]]></event_payload>"
        
        # Queue task with Taskiq
        kiq_msg = await run_background_agent.kiq(
            agent_name=agent_name, 
            prompt=xml_payload, 
            user_id="webhook"  # Using a system user for webhook operations
        )
        return {"status": "accepted", "task_id": kiq_msg.task_id}
        
    except Exception as e:
        logger.error(f"Error processing webhook: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
