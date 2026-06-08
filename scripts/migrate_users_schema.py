import os
import pyetcd

def migrate_users():
    client = pyetcd.client(
        host=os.getenv("ETCD_HOST", "127.0.0.1"),
        port=int(os.getenv("ETCD_PORT", 2379))
    )
    
    print("Scanning /users/ prefix...")
    # Get all keys under the old prefix
    records = list(client.get_prefix("/users/"))
    print(f"Found {len(records)} records to migrate.")
    
    migrated_count = 0
    
    for value, metadata in records:
        if not value:
            continue
            
        old_key = metadata.key.decode('utf-8')
        parts = old_key.strip('/').split('/')
        
        # We only care about keys that start with "users"
        if len(parts) < 2 or parts[0] != "users":
            continue
            
        # Ignore keys that are already in the new format (e.g. /users/profiles/...)
        if parts[1] in ("profiles", "secrets", "variables"):
            continue
            
        user_id = parts[1]
        
        # Determine the new key path
        if len(parts) == 2:
            # It's a profile: /users/{user_id} -> /users/profiles/{user_id}
            new_key = f"/users/profiles/{user_id}"
        elif len(parts) == 3 and parts[2] == "secrets":
            # It's a secret: /users/{user_id}/secrets -> /users/secrets/{user_id}
            new_key = f"/users/secrets/{user_id}"
        elif len(parts) == 3 and parts[2] == "variables":
            # It's a variable: /users/{user_id}/variables -> /users/variables/{user_id}
            new_key = f"/users/variables/{user_id}"
        else:
            print(f"Skipping unmapped key format: {old_key}")
            continue
            
        # Write to the new path
        client.put(new_key, value)
        
        # Delete the old path
        client.delete(old_key)
        
        print(f"Migrated: {old_key} -> {new_key}")
        migrated_count += 1
        
    print(f"Migration complete. {migrated_count} records migrated.")

if __name__ == "__main__":
    migrate_users()
