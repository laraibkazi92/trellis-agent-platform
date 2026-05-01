import os
import json
import uuid
import logging
from typing import Optional, Dict, Tuple, Any

logger = logging.getLogger(__name__)

class EtcdQueue:
    def __init__(self):
        from core.auth import IdentityManager
        self.etcd = IdentityManager(
            host=os.getenv("ETCD_HOST", "127.0.0.1"),
            port=int(os.getenv("ETCD_PORT", 2379))
        ).client
        self.prefix_pending = "/queue/pending/"
        self.prefix_processing = "/queue/processing/"
        self.prefix_completed = "/queue/completed/"
        self.prefix_failed = "/queue/failed/"

    def push(self, payload: Dict[str, Any]) -> str:
        task_id = str(uuid.uuid4())
        key = f"{self.prefix_pending}{task_id}"
        self.etcd.put(key, json.dumps(payload))
        logger.info(f"Enqueued task {task_id}")
        return task_id

    def get_pending(self) -> Optional[Tuple[str, Dict[str, Any]]]:
        for value, metadata in self.etcd.get_prefix(self.prefix_pending):
            key = metadata.key.decode('utf-8')
            task_id = key.replace(self.prefix_pending, "")
            payload = json.loads(value.decode('utf-8'))
            return task_id, payload
        return None

    def move_to_processing(self, task_id: str, payload: Dict[str, Any], ttl_seconds: int = 3600):
        # Create a lease for processing state
        lease = self.etcd.lease(ttl_seconds)
        processing_key = f"{self.prefix_processing}{task_id}"
        pending_key = f"{self.prefix_pending}{task_id}"
        
        # Transaction: if pending key exists, delete it and put to processing
        success, _ = self.etcd.transaction(
            compare=[self.etcd.transactions.version(pending_key) > 0],
            success=[
                self.etcd.transactions.delete(pending_key),
                self.etcd.transactions.put(processing_key, json.dumps(payload), lease=lease)
            ],
            failure=[]
        )
        return success

    def move_to_completed(self, task_id: str, payload: Dict[str, Any]):
        processing_key = f"{self.prefix_processing}{task_id}"
        completed_key = f"{self.prefix_completed}{task_id}"
        
        self.etcd.transaction(
            compare=[],
            success=[
                self.etcd.transactions.delete(processing_key),
                self.etcd.transactions.put(completed_key, json.dumps(payload))
            ],
            failure=[]
        )
        logger.info(f"Task {task_id} completed")

    def move_to_failed(self, task_id: str, payload: Dict[str, Any], error: str):
        processing_key = f"{self.prefix_processing}{task_id}"
        failed_key = f"{self.prefix_failed}{task_id}"
        payload['error'] = error
        
        self.etcd.transaction(
            compare=[],
            success=[
                self.etcd.transactions.delete(processing_key),
                self.etcd.transactions.put(failed_key, json.dumps(payload))
            ],
            failure=[]
        )
        logger.error(f"Task {task_id} failed: {error}")
