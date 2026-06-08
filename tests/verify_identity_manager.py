import os

# SET THIS BEFORE ANY OTHER IMPORTS
os.environ["DEV_MODE"] = "true"

import json
import warnings
from core.auth import IdentityManager
from core.models import Identity, IdentityType

def test_identity_manager_refactor():
    # Initialize IdentityManager
    # Assuming etcd is running and accessible on localhost:2379
    mgr = IdentityManager(host="127.0.0.1", port=2379)
    
    user_id = "test-user-refactor"
    agent_id = "test-agent-refactor"
    
    # 1. Test Legacy Methods (should still work and use old paths)
    print("Testing legacy methods...")
    mgr.save_user_secrets(user_id, {"key": "user-secret"})
    mgr.save_user_variables(user_id, {"var": "user-var"})
    
    secrets = mgr.get_user_secrets(user_id)
    vars = mgr.get_user_variables(user_id)
    
    assert secrets == {"key": "user-secret"}
    assert vars == {"var": "user-var"}
    print("Legacy methods verified.")

    # 2. Test New Identity Config Methods (should use new paths)
    print("\nTesting new identity config methods...")
    user_identity = Identity(id=user_id, type=IdentityType.USER)
    agent_identity = Identity(id=agent_id, type=IdentityType.WORKFLOW)
    
    mgr.save_identity_config(user_identity, "secrets", {"new-key": "new-user-secret"})
    mgr.save_identity_config(agent_identity, "secrets", {"agent-key": "agent-secret"})
    
    user_new_secrets = mgr.get_identity_config(user_identity, "secrets")
    agent_secrets = mgr.get_identity_config(agent_identity, "secrets")
    
    assert user_new_secrets == {"new-key": "new-user-secret"}
    assert agent_secrets == {"agent-key": "agent-secret"}
    
    # Verify they are separate from legacy paths
    assert mgr.get_user_secrets(user_id) == {"key": "user-secret"}
    print("New identity config methods verified.")

    # 3. Test Resolved Config
    print("\nTesting resolved config...")
    # Set system config
    system_identity = Identity(id="system", type=IdentityType.SYSTEM)
    mgr.save_identity_config(system_identity, "variables", {"global-var": "global", "override-var": "global"})
    
    # Set user config
    mgr.save_identity_config(user_identity, "variables", {"user-var": "local", "override-var": "user"})
    
    resolved = mgr.get_resolved_config(user_identity, "variables")
    assert resolved["global-var"] == "global"
    assert resolved["user-var"] == "local"
    assert resolved["override-var"] == "user" # User takes precedence
    print("Resolved config verified.")

    # 4. Test Scoped fetching
    print("\nTesting scoped fetching...")
    scoped = mgr.get_identity_config(user_identity, "variables", keys=["user-var"])
    assert scoped == {"user-var": "local"}
    assert "override-var" not in scoped
    print("Scoped fetching verified.")

if __name__ == "__main__":
    try:
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            test_identity_manager_refactor()
            print("\nAll refactor tests passed successfully!")
            # Check for warnings
            deprecations = [item for item in w if issubclass(item.category, DeprecationWarning)]
            print(f"Captured {len(deprecations)} deprecation warnings as expected.")
            for warn in deprecations:
                print(f"  - {warn.message}")
    except Exception as e:
        print(f"Test failed: {e}")
        import traceback
        traceback.print_exc()
