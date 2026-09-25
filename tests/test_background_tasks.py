"""Regression tests for Phase 5 (Cycle 4) Task 5.1 — fire-and-forget safety.

Both `core.hub` and `core.host` must expose a module-level `_background_tasks`
set and a `_spawn_background(coro, name)` helper that creates an asyncio task,
tracks it, discards it when it completes, and routes failures through the
module logger instead of swallowing them.
"""

import asyncio
import logging

import pytest

from core import host, hub


@pytest.mark.parametrize("module", [hub, host], ids=["hub", "host"])
def test_spawn_background_logs_and_discards_on_exception(module, caplog):
    async def boom():
        raise RuntimeError("kaboom")

    async def scenario():
        task = module._spawn_background(boom(), "boom-task")
        try:
            await task
        except RuntimeError:
            pass
        await asyncio.sleep(0)
        return task

    with caplog.at_level(logging.ERROR):
        task = asyncio.run(scenario())

    assert "Background task boom-task failed" in caplog.text
    assert "kaboom" in caplog.text
    assert task not in module._background_tasks


@pytest.mark.parametrize("module", [hub, host], ids=["hub", "host"])
def test_spawn_background_ignores_cancellation(module, caplog):
    async def scenario():
        blocker = asyncio.Event()

        async def wait_forever():
            await blocker.wait()

        task = module._spawn_background(wait_forever(), "cancelled-task")
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        await asyncio.sleep(0)
        return task

    with caplog.at_level(logging.ERROR):
        task = asyncio.run(scenario())

    assert "Background task" not in caplog.text
    assert task not in module._background_tasks


@pytest.mark.parametrize("module", [hub, host], ids=["hub", "host"])
def test_spawn_background_discards_on_success(module, caplog):
    async def fine():
        return "ok"

    async def scenario():
        task = module._spawn_background(fine(), "fine-task")
        result = await task
        await asyncio.sleep(0)
        return task, result

    with caplog.at_level(logging.ERROR):
        task, result = asyncio.run(scenario())

    assert result == "ok"
    assert task.done()
    assert task not in module._background_tasks
    assert [record for record in caplog.records if record.levelno >= logging.ERROR] == []
