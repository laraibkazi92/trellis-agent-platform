import os
import json
import logging

# Set env before imports

from core.auth import IdentityManager
from core.models import Identity, IdentityType

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def migrate():
    mgr = IdentityManager(host=os.getenv("ETCD_HOST", "127.0.0.1"), port=int(os.getenv("ETCD_PORT", 2379)))
    client = mgr.client

    # 1. Migrate Global Secrets & Variables
    logger.info("Migrating Global Secrets and Variables...")
    global_secrets = mgr.get_global_secrets()
    if global_secrets:
        mgr.save_identity_config(Identity(id="system", type=IdentityType.SYSTEM), "secrets", global_secrets)
        logger.info("  - Migrated Global Secrets")

    global_variables = mgr.get_global_variables()
    if global_variables:
        mgr.save_identity_config(Identity(id="system", type=IdentityType.SYSTEM), "variables", global_variables)
        logger.info("  - Migrated Global Variables")

    # 2. Migrate User Secrets & Variables
    logger.info("Migrating User Secrets...")
    for value, metadata in client.get_prefix("/users/secrets/"):
        key_str = metadata.key.decode('utf-8')
        user_id = key_str.split('/')[-1]
        
        if user_id.startswith("svc_agent_"):
            # This is an agent identity
            agent_name = user_id.replace("svc_agent_", "")
            identity = Identity(id=agent_name, type=IdentityType.WORKFLOW)
            logger.info(f"  - Detected Agent Identity: {agent_name}")
        else:
            # This is a user identity
            identity = Identity(id=user_id, type=IdentityType.USER)
            logger.info(f"  - Detected User Identity: {user_id}")

        data = mgr._get_kv(key_str, decrypt=True)
        if data:
            mgr.save_identity_config(identity, "secrets", data)
            logger.info(f"    - Migrated secrets to {identity.get_etcd_path('secrets')}")

    logger.info("Migrating User Variables...")
    for value, metadata in client.get_prefix("/users/variables/"):
        key_str = metadata.key.decode('utf-8')
        user_id = key_str.split('/')[-1]
        
        # Variables usually don't have agents in current impl, but handle just in case
        if user_id.startswith("svc_agent_"):
            agent_name = user_id.replace("svc_agent_", "")
            identity = Identity(id=agent_name, type=IdentityType.WORKFLOW)
        else:
            identity = Identity(id=user_id, type=IdentityType.USER)

        data = mgr._get_kv(key_str, decrypt=False)
        if data:
            mgr.save_identity_config(identity, "variables", data)
            logger.info(f"    - Migrated variables to {identity.get_etcd_path('variables')}")

    logger.info("Migration Complete!")

if __name__ == "__main__":
    migrate()
