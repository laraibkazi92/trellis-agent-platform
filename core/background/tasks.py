# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import asyncio
import logging

logger = logging.getLogger(__name__)

background_tasks: set[asyncio.Task] = set()


def spawn_background(coro, name: str) -> asyncio.Task:
    task = asyncio.create_task(coro, name=name)
    background_tasks.add(task)

    def _done(t: asyncio.Task):
        background_tasks.discard(t)
        if not t.cancelled() and t.exception() is not None:
            logger.error("Background task %s failed: %s", name, t.exception())

    task.add_done_callback(_done)
    return task


async def drain_background_tasks(timeout: float = 5.0) -> None:
    pending = {t for t in background_tasks if not t.done()}
    if not pending:
        return
    _, still_pending = await asyncio.wait(pending, timeout=timeout)
    for task in still_pending:
        task.cancel()
    if still_pending:
        logger.warning("Cancelled %d background task(s) that did not finish within %.1fs", len(still_pending), timeout)
