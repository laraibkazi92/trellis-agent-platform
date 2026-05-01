import time
import asyncio
import logging
from typing import Dict, Any
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from core.background.queue import EtcdQueue

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()
queue = EtcdQueue()

def get_identity_mgr():
    from core.host import identity_mgr
    return identity_mgr

async def run_cron_job(agent_name: str):
    identity_mgr = get_identity_mgr()
    
    # Mitigate clock drift: round time up slightly so node firing at 59.9s and node at 00.1s hit same minute window
    current_minute = int(time.time() + 2) // 60
    lock_key = f"/lock/cron/{agent_name}/{current_minute}"
    
    try:
        # Try to acquire lock by creating the key if it doesn't exist. TTL 120 seconds.
        lease = identity_mgr.client.lease(120)
        success, _ = identity_mgr.client.transaction(
            compare=[identity_mgr.client.transactions.version(lock_key) == 0],
            success=[identity_mgr.client.transactions.put(lock_key, "locked", lease=lease)],
            failure=[]
        )
        
        if not success:
            logger.debug(f"Cron for {agent_name} already triggered by another instance this minute.")
            return

        logger.info(f"Cron triggered for {agent_name}. Enqueueing task.")
        
        task_payload = {
            "agent_name": agent_name,
            "trigger_type": "cron",
            "prompt": "<event_payload>\nScheduled cron execution\n</event_payload>"
        }
        
        # Enqueue
        await asyncio.to_thread(queue.push, task_payload)
    except Exception as e:
        logger.error(f"Error executing cron job for {agent_name}: {e}")

async def start_scheduler():
    identity_mgr = get_identity_mgr()
    
    logger.info("Starting background agent cron scheduler...")
    
    try:
        agent_names = await asyncio.to_thread(identity_mgr.list_agents)
        for name in agent_names:
            config_data = await asyncio.to_thread(identity_mgr.get_agent_config, name)
            if config_data and config_data.get("type") == "background":
                trigger = config_data.get("trigger", {})
                if trigger.get("type") == "cron":
                    expression = trigger.get("expression")
                    if expression:
                        try:
                            # Parse standard cron expression
                            cron_trigger = CronTrigger.from_crontab(expression)
                            scheduler.add_job(
                                run_cron_job,
                                trigger=cron_trigger,
                                args=[name],
                                id=f"cron_{name}",
                                replace_existing=True
                            )
                            logger.info(f"Registered cron job for {name} with schedule '{expression}'")
                        except Exception as e:
                            logger.error(f"Invalid cron expression for {name}: {e}")
    except Exception as e:
        logger.error(f"Failed to initialize cron jobs: {e}")
        
    scheduler.start()
