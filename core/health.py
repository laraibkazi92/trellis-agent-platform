import json
import os
import threading
from typing import Optional, Dict, Any

from core.auth import IdentityManager
import core.health_db as health_db

class HealthMonitor:
    def __init__(self, identity_mgr: IdentityManager):
        self.identity_mgr = identity_mgr
        self.failure_threshold = int(os.getenv("HEALTH_FAILURE_THRESHOLD", "5"))
        # Initialize the health events database
        health_db.init_db()

    def record_event(self, entity_type: str, name: str, is_success: bool, error_details: Optional[str] = None) -> Dict[str, Any]:
        """
        Record a health event for an entity.
        Global failures (is_success=False) increment the failure counter.
        User-scoped failures should not be recorded as failures here.
        """
        current_status = self.get_status(entity_type, name)
        old_status_val = current_status.get("status", "Online")
        
        if is_success:
            current_status["status"] = "Online"
            current_status["consecutive_failures"] = 0
            current_status["last_error"] = None
        else:
            current_status["consecutive_failures"] = current_status.get("consecutive_failures", 0) + 1
            if error_details:
                current_status["last_error"] = error_details[:1000] # Truncate to prevent etcd bloat
            if current_status["consecutive_failures"] >= self.failure_threshold:
                current_status["status"] = "Offline"
                
        new_status_val = current_status["status"]
        
        # If the status changed, log it to the sqlite db
        if old_status_val != new_status_val or (not is_success and current_status["consecutive_failures"] == 1):
            # Also log if it's the first failure to track intermittent errors if needed, 
            # but the spec says "state changes (e.g., Online to Offline)". Let's stick to state change.
            pass
            
        if old_status_val != new_status_val:
            # Log the change
            health_db.log_event(entity_type, name, new_status_val, current_status.get("last_error"))
            
            # Run cleanup synchronously; it's throttled internally to run at most once a day
            health_db.cleanup_old_events(30)

        self.identity_mgr.save_health_status(entity_type, name, current_status)
        return current_status

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
        return self.record_event(entity_type, name, is_success=True)
