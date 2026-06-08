import os
import logging

# Set env before imports

from core.auth import IdentityManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def migrate_paths():
    mgr = IdentityManager(host=os.getenv("ETCD_HOST", "127.0.0.1"), port=int(os.getenv("ETCD_PORT", 2379)))
    client = mgr.client

    logger.info("Scanning for /identities/agent/ keys...")
    
    # Get all keys under /identities/agent/
    results = client.get_prefix("/identities/agent/")
    
    count = 0
    for value, metadata in results:
        old_key = metadata.key.decode('utf-8')
        new_key = old_key.replace("/identities/agent/", "/identities/workflow/")
        
        logger.info(f"Migrating {old_key} -> {new_key}")
        
        # Copy value to new key
        client.put(new_key, value)
        
        # Delete old key
        client.delete(old_key)
        count += 1

    logger.info(f"Migration complete. Migrated {count} keys.")

if __name__ == "__main__":
    migrate_paths()
