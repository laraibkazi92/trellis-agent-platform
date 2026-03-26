import etcd3gw
import json
from typing import Optional
from .database import settings

def get_etcd_client():
    host_port = settings.etcd_endpoint.replace("http://", "").replace("https://", "")
    host, port = host_port.split(":") if ":" in host_port else (host_port, "2379")
    return etcd3gw.client(host=host, port=int(port))

def set_etcd_secret(key: str, value: dict):
    """Store secret in etcd"""
    client = get_etcd_client()
    client.put(key, json.dumps(value))

def get_etcd_secret(key: str) -> dict | None:
    """Retrieve secret from etcd"""
    client = get_etcd_client()
    results = client.get(key)
    if results and len(results) > 0:
        value = results[0]
        if isinstance(value, tuple):
            value = value[0]
        return json.loads(value.decode() if isinstance(value, bytes) else value)
    return None

def list_etcd_secrets(prefix: str = "") -> list:
    """List secret keys in etcd"""
    client = get_etcd_client()
    if prefix:
        generator = client.get_prefix(prefix)
    else:
        generator = client.get_all()
    
    keys = []
    if generator:
        for item in generator:
            if isinstance(item, tuple) and len(item) == 2:
                value, metadata = item
                if isinstance(metadata, dict):
                    k = metadata.get(b'key') or metadata.get('key')
                    if k:
                        keys.append(k.decode() if isinstance(k, bytes) else k)
    return keys
