# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Live resource limits: an OOM kill takes its own container, nobody else's.

The probe declares ``limits.memory_mb: 64`` and allocates past it while a second
call is in flight. The hog must die non-zero (SIGKILL from the cgroup OOM
killer) and the concurrent call must still succeed -- a shared cgroup or a
runner that killed the wrong container would show up as both failing.
"""

import asyncio

import pytest

pytestmark = pytest.mark.runsc


def test_memory_kill_stays_inside_its_own_container(live):
    async def scenario():
        hog = asyncio.create_task(live.acall("probe_limits", {}))
        # Give the hog time to enter its allocation loop, then hold a slot in a
        # second container that spans the kill.
        await asyncio.sleep(0.3)
        survivor = await live.acall("probe_sleep", {"seconds": 2}, deadline_ms=30_000)
        return await hog, survivor

    hog, survivor = asyncio.run(scenario())

    assert hog.exit_code != 0, "the container allocating past its memory limit was not killed"
    assert survivor.exit_code == 0, survivor.stderr
