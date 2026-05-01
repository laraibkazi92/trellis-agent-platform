import asyncio
import logging
import threading
import time
from core.background.queue import EtcdQueue

logger = logging.getLogger(__name__)

class BackgroundWorker:
    def __init__(self):
        self.queue = EtcdQueue()
        self._watch_cancel = None

    async def _process_task(self, task_id: str, payload: dict):
        from core.host import manager
        agent_name = payload.get("agent_name")
        if not agent_name or agent_name not in manager.agents:
            self.queue.move_to_failed(task_id, payload, f"Agent {agent_name} not found")
            return

        agent = manager.agents[agent_name]
        trigger_data = payload.get("prompt", "")
        
        try:
            # Run agent
            result = await agent.run(trigger_data)
            payload["result"] = result.output
            self.queue.move_to_completed(task_id, payload)
        except Exception as e:
            self.queue.move_to_failed(task_id, payload, str(e))

    async def start(self, concurrency_limit: int = 5):
        semaphore = asyncio.Semaphore(concurrency_limit)
        logger.info("Background worker loop started")
        
        loop = asyncio.get_running_loop()
        wakeup_queue = asyncio.Queue()
        wakeup_queue.put_nowait(True) # initial wakeup
        
        def watch_etcd():
            while True:
                try:
                    events_iterator, cancel = self.queue.etcd.watch_prefix(self.queue.prefix_pending)
                    self._watch_cancel = cancel
                    for event in events_iterator:
                        loop.call_soon_threadsafe(wakeup_queue.put_nowait, True)
                except Exception as e:
                    if self._watch_cancel is None:
                        break
                    logger.error(f"Etcd watch error, retrying in 5s: {e}")
                    time.sleep(5)
                    
        watch_thread = threading.Thread(target=watch_etcd, daemon=True)
        watch_thread.start()
        
        while True:
            try:
                # Drain wakeup queue
                while not wakeup_queue.empty():
                    try:
                        wakeup_queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break

                task = self.queue.get_pending()
                if task:
                    task_id, payload = task
                    if self.queue.move_to_processing(task_id, payload):
                        # Launch task with semaphore
                        async def bounded_process(t_id, p):
                            async with semaphore:
                                await self._process_task(t_id, p)
                        
                        asyncio.create_task(bounded_process(task_id, payload))
                        
                        # Schedule another check immediately
                        wakeup_queue.put_nowait(True)
                else:
                    # Wait for watch event or fallback timeout
                    try:
                        await asyncio.wait_for(wakeup_queue.get(), timeout=30.0)
                    except asyncio.TimeoutError:
                        # Periodically wake up just in case watch dropped an event
                        wakeup_queue.put_nowait(True)
            except Exception as e:
                import traceback
                traceback.print_exc()
                logger.error(f"Worker loop error: {e}", exc_info=True)
                await asyncio.sleep(5)

    def stop(self):
        if self._watch_cancel:
            cancel_func = self._watch_cancel
            self._watch_cancel = None # signal loop to break
            try:
                cancel_func()
            except Exception:
                pass

worker = BackgroundWorker()
