# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Per-site call rate limiting for the edge relay.

One edge must not be able to pin the hub's call path, and a compromised token
should not turn into an unbounded tool-call firehose. The limiter is a token
bucket per site: capacity ``burst``, refilled at ``rate_per_min``.

Deliberately in-process, like the site map: the relay runs one worker (see
docker-compose.yml), so a shared store would add a dependency for no gain.
"""

from __future__ import annotations

import time
from typing import Dict, Optional

DEFAULT_RATE_PER_MIN = 120
MAX_RATE_PER_MIN = 6_000


class TokenBucket:
    """Classic token bucket. ``allow`` consumes one token when available."""

    __slots__ = ("rate_per_second", "capacity", "tokens", "updated")

    def __init__(self, rate_per_min: float, burst: Optional[int] = None):
        self.rate_per_second = max(rate_per_min, 1.0) / 60.0
        self.capacity = max(1, int(burst if burst is not None else rate_per_min))
        self.tokens = float(self.capacity)
        self.updated = time.monotonic()

    def allow(self, now: Optional[float] = None) -> bool:
        now = time.monotonic() if now is None else now
        elapsed = max(0.0, now - self.updated)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate_per_second)
        self.updated = now
        if self.tokens < 1.0:
            return False
        self.tokens -= 1.0
        return True


def normalise_rate(value: object) -> int:
    """Clamp an operator-supplied rate; junk falls back to the default."""
    try:
        rate = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return DEFAULT_RATE_PER_MIN
    return max(1, min(rate, MAX_RATE_PER_MIN))


class SiteLimiter:
    """One bucket per site, rebuilt when its configured rate changes."""

    def __init__(self, default_rate_per_min: int = DEFAULT_RATE_PER_MIN):
        self.default_rate_per_min = normalise_rate(default_rate_per_min)
        self._buckets: Dict[str, tuple[int, TokenBucket]] = {}

    def allow(self, site: str, rate_per_min: Optional[int] = None) -> bool:
        rate = normalise_rate(rate_per_min if rate_per_min is not None else self.default_rate_per_min)
        entry = self._buckets.get(site)
        if entry is None or entry[0] != rate:
            entry = (rate, TokenBucket(rate))
            self._buckets[site] = entry
        return entry[1].allow()

    def forget(self, site: str) -> None:
        self._buckets.pop(site, None)
