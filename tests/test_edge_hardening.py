# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""P2 hardening tests: per-site rate limiting, the payload-free audit trail, and
(v0.7.2 R1) the caller identity a call frame is allowed to name."""

import asyncio
import json
import logging

import pytest

from core import proxy
from core.models import ToolConfig
from services.edge_relay import audit
from services.edge_relay.ratelimit import (
    DEFAULT_RATE_PER_MIN,
    SiteLimiter,
    TokenBucket,
    normalise_rate,
)


# --- token bucket -------------------------------------------------------------------


def test_bucket_allows_burst_then_refuses():
    bucket = TokenBucket(rate_per_min=60, burst=3)
    now = 1000.0

    assert [bucket.allow(now) for _ in range(4)] == [True, True, True, False]


def test_bucket_refills_at_the_configured_rate():
    bucket = TokenBucket(rate_per_min=60, burst=1)  # one token per second
    now = 1000.0

    assert bucket.allow(now) is True
    assert bucket.allow(now) is False
    assert bucket.allow(now + 0.5) is False
    assert bucket.allow(now + 1.0) is True


def test_bucket_never_exceeds_capacity():
    bucket = TokenBucket(rate_per_min=600, burst=2)
    for _ in range(100):
        bucket.allow(1000.0)

    # A long idle window must not let a later burst exceed capacity.
    assert bucket.allow(2000.0) is True
    assert bucket.allow(2000.0) is True
    assert bucket.allow(2000.0) is False


# --- limiter ------------------------------------------------------------------------


def test_limiter_is_per_site():
    limiter = SiteLimiter(default_rate_per_min=60)

    assert limiter.allow("site-a") is True
    assert limiter.allow("site-b") is True
    assert limiter.allow("site-a") is True


def test_limiter_honours_a_site_override_and_rebuilds_on_change():
    limiter = SiteLimiter(default_rate_per_min=60)

    # A rate of 1/min gives a capacity of one call.
    assert limiter.allow("site-a", rate_per_min=1) is True
    assert limiter.allow("site-a", rate_per_min=1) is False
    # Raising the limit rebuilds the bucket instead of keeping the empty one.
    assert limiter.allow("site-a", rate_per_min=600) is True


def test_limiter_can_forget_a_site():
    limiter = SiteLimiter(default_rate_per_min=1)
    assert limiter.allow("site-a") is True
    assert limiter.allow("site-a") is False
    limiter.forget("site-a")
    assert limiter.allow("site-a") is True


@pytest.mark.parametrize(
    "raw, expected",
    [
        (None, DEFAULT_RATE_PER_MIN),
        ("", DEFAULT_RATE_PER_MIN),
        ("nonsense", DEFAULT_RATE_PER_MIN),
        (0, 1),
        (-5, 1),
        ("42", 42),
        (999_999, 6_000),
    ],
)
def test_normalise_rate_clamps_and_falls_back(raw, expected):
    assert normalise_rate(raw) == expected


# --- audit --------------------------------------------------------------------------


def _capture_audit():
    records = []

    class _Handler(logging.Handler):
        def emit(self, record):
            records.append(json.loads(record.getMessage()))

    handler = _Handler()
    audit.logger.addHandler(handler)
    return records, handler


def test_audit_line_carries_metadata_and_no_payload():
    records, handler = _capture_audit()
    try:
        audit.record(
            "call",
            site="plant-floor",
            tool="boiler_status",
            call_id="abc123",
            user="dev-user@local.host",
            outcome="ok",
            ms=12,
            args_bytes=18,
            result_bytes=210,
        )
    finally:
        audit.logger.removeHandler(handler)

    assert records[0]["ts"].endswith("+00:00")
    assert records == [
        {
            "ts": records[0]["ts"],
            "event": "call",
            "site": "plant-floor",
            "tool": "boiler_status",
            "call_id": "abc123",
            "user": "dev-user@local.host",
            "outcome": "ok",
            "ms": 12,
            "args_bytes": 18,
            "result_bytes": 210,
        }
    ]


def test_audit_omits_absent_fields():
    records, handler = _capture_audit()
    try:
        audit.record("disconnect", site="plant-floor", outcome="closed")
    finally:
        audit.logger.removeHandler(handler)

    assert records[0]["ts"].endswith("+00:00")
    assert records == [
        {
            "ts": records[0]["ts"],
            "event": "disconnect",
            "site": "plant-floor",
            "outcome": "closed",
        }
    ]


def test_audit_never_writes_arguments_or_results(monkeypatch):
    """The record signature has no payload parameters; this pins that no caller can
    smuggle one in through extra metadata."""
    records, handler = _capture_audit()
    try:
        with pytest.raises(TypeError):
            audit.record(
                "call",
                site="s",
                outcome="ok",
                args={"password": "hunter2"},  # type: ignore[call-arg]
            )
    finally:
        audit.logger.removeHandler(handler)
    assert records == []


def test_configure_always_attaches_a_handler(monkeypatch):
    """Audit must never go silent just because no file path is configured."""
    monkeypatch.setattr(audit, "_configured", False)
    monkeypatch.delenv("EDGE_AUDIT_LOG", raising=False)
    audit.logger.handlers.clear()

    audit.configure()

    assert audit.logger.handlers
    assert any(isinstance(h, logging.StreamHandler) for h in audit.logger.handlers)


def test_configure_falls_back_to_stderr_when_the_file_cannot_be_opened(monkeypatch, tmp_path):
    monkeypatch.setattr(audit, "_configured", False)
    audit.logger.handlers.clear()
    blocked = tmp_path / "not-a-dir"
    blocked.write_text("x")
    monkeypatch.setenv("EDGE_AUDIT_LOG", str(blocked / "audit.log"))

    audit.configure()

    assert any(isinstance(h, logging.StreamHandler) for h in audit.logger.handlers)


# --- caller identity (v0.7.2 R1) -----------------------------------------------------
#
# The relay is the only verifier on this path: it authenticated the caller, checked the
# token and sends the claims it derived. Everything the edge believes about a caller
# therefore comes from the frame -- never from the tool's arguments, the edge's own
# environment, or a token (there is none to read any more).


FRAME_IDENTITY = {
    "user": "frame-user",
    "user_email": "frame@example.com",
    "agent": "frame-agent",
    "groups": ["frame-group"],
    "run_id": "frame-run",
    "parent_run_id": "frame-parent",
}


def _identity_tool(tmp_path):
    """A tool that declares inputs named exactly like the identity fields."""
    tool_dir = tmp_path / "demo"
    tool_dir.mkdir()
    (tool_dir / "main.py").write_text("print('{}')\n", encoding="utf-8")
    config = ToolConfig(
        name="demo",
        description="d",
        runtime="python",
        entrypoint="main.py",
        inputs={
            "user": {"type": "string"},
            "agent": {"type": "string"},
            "groups": {"type": "string"},
        },
    )
    return config, tool_dir


def test_the_frame_is_the_only_identity_source(tmp_path, monkeypatch):
    """Arguments and the edge's own env cannot name a caller."""
    seen = {}

    async def fake_execute(
        config, tool_dir, arguments, *, env, on_health=None, identity=None
    ):
        seen["identity"] = identity
        seen["env"] = env
        return {"ok": True}

    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", fake_execute)
    # An identity left in the edge process must never become this caller's.
    monkeypatch.setenv("TRELLIS_USER_ID", "env-user")
    monkeypatch.setenv("TRELLIS_USER_EMAIL", "env@example.com")
    config, tool_dir = _identity_tool(tmp_path)

    frame = asyncio.run(
        proxy.handle_call(
            {"demo": (config, tool_dir)},
            {
                "t": "call",
                "id": "c1",
                "tool": "demo",
                "args": {
                    "user": "arg-user",
                    "agent": "arg-agent",
                    "groups": "arg-groups",
                },
                **FRAME_IDENTITY,
            },
        )
    )

    assert frame["ok"] is True
    assert seen["identity"] == FRAME_IDENTITY
    # The tool's env is rebuilt from the frame too, so the legacy vars are replaced.
    assert seen["env"]["TRELLIS_USER_ID"] == "frame-user"
    assert seen["env"]["TRELLIS_USER_EMAIL"] == "frame@example.com"


def test_a_frame_token_is_never_forwarded_to_the_runner(tmp_path, monkeypatch):
    """A v0.7.1 relay still sends one; R1's edge must not pass it on."""
    seen = {}

    async def fake_execute(
        config, tool_dir, arguments, *, env, on_health=None, identity=None
    ):
        seen["identity"] = identity
        return {"ok": True}

    monkeypatch.setattr(proxy.tool_runtime, "execute_tool", fake_execute)
    config, tool_dir = _identity_tool(tmp_path)

    asyncio.run(
        proxy.handle_call(
            {"demo": (config, tool_dir)},
            {
                "t": "call",
                "id": "c1",
                "tool": "demo",
                "args": {},
                "agent_token": "t1.payload.signature",
                **FRAME_IDENTITY,
            },
        )
    )

    assert "agent_token" not in seen["identity"]
