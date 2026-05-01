import asyncio
import logging
from core.background.queue import EtcdQueue

logger = logging.getLogger(__name__)
queue = EtcdQueue()

async def process_task(task_id: str, payload: dict):
    from core.host import manager
    agent_name = payload.get("agent_name")
    if not agent_name or agent_name not in manager.agents:
        queue.move_to_failed(task_id, payload, f"Agent {agent_name} not found")
        return

    agent = manager.agents[agent_name]
    trigger_data = payload.get("trigger_data", "")
    
    try:
        # Run agent
        result = await agent.run(trigger_data)
        payload["result"] = result.output
        queue.move_to_completed(task_id, payload)
    except Exception as e:
        queue.move_to_failed(task_id, payload, str(e))

async def worker_loop(concurrency_limit: int = 5):
    semaphore = asyncio.Semaphore(concurrency_limit)
    logger.info("Background worker loop started")
    
    while True:
        try:
            task = queue.get_pending()
            if task:
                task_id, payload = task
                if queue.move_to_processing(task_id, payload):
                    # Launch task with semaphore
                    async def bounded_process(t_id, p):
                        async with semaphore:
                            await process_task(t_id, p)
                    
                    asyncio.create_task(bounded_process(task_id, payload))
            else:
                await asyncio.sleep(1) # Wait before polling again
        except Exception as e:
            import traceback
            traceback.print_exc()
            logger.error(f"Worker loop error: {e}", exc_info=True)
            await asyncio.sleep(5)
