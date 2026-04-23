import json
from typing import Optional, Dict, Any

from core.auth import IdentityManager

class HealthMonitor:
    def __init__(self, identity_mgr: IdentityManager):
        self.identity_mgr = identity_mgr

    def record_event(self, entity_type: str, name: str, is_success: bool, error_details: Optional[str] = None) -> Dict[str, Any]:
        """
        Record a health event for an entity.
        Global failures (is_success=False) increment the failure counter.
        User-scoped failures should not be recorded as failures here.
        """
        return self.identity_mgr.record_health_event(entity_type, name, is_success, error_details)

    def get_status(self, entity_type: str, name: str) -> Dict[str, Any]:
        """
        Retrieve the current health status of an entity.
        """
        status = self.identity_mgr.get_health_status(entity_type, name)
        if status is None:
            return {"status": "Online", "consecutive_failures": 0, "last_error": None}
        return status

    def reset_status(self, entity_type: str, name: str) -> Dict[str, Any]:
        """
        Manually reset the health status to Online.
        """
        # A manual success event resets everything
        return self.identity_mgr.record_health_event(entity_type, name, is_success=True)
