# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Declarative guardrails: evaluation, merge/cache semantics, hit metrics, hooks.

Everything runs without etcd, network or sleeps. Framework defaults are served by an
in-memory fake identity manager, and the hit-counter tests reuse the in-memory etcd
client contract from ``tests/test_metrics_recording.py``. Host route coverage drives
``host.chat_completions`` directly (the harness used by
``tests/test_agent_gateway_host_access.py``) rather than through a TestClient/lifespan.
"""

import asyncio
import json
import threading
from types import SimpleNamespace

import pytest

import core.memory as memory
import core.tasks as tasks
from core import auth, guardrails, host
from core.auth import IdentityManager


# --- Fake etcd client / manager (same contract as test_metrics_recording) ------

class _Meta:
    def __init__(self, key):
        self.key = key


class FakeClient:
    def __init__(self):
        self.store = {}
        self.lock_names = []
        self._locks = {}
        self._guard = threading.Lock()

    @staticmethod
    def _as_bytes(value):
        return value.encode("utf-8") if isinstance(value, str) else value

    def get(self, path):
        with self._guard:
            return self.store.get(path), None

    def put(self, path, value):
        with self._guard:
            self.store[path] = self._as_bytes(value)

    def put_if_not_exists(self, path, value):
        with self._guard:
            if path in self.store:
                return False
            self.store[path] = self._as_bytes(value)
            return True

    def replace(self, path, old, new):
        with self._guard:
            current = self.store.get(path)
            if current is None or current != self._as_bytes(old):
                return False
            self.store[path] = self._as_bytes(new)
            return True

    def get_prefix(self, prefix):
        with self._guard:
            keys = sorted(key for key in list(self.store) if key.startswith(prefix))
            return [(self.store[key], _Meta(key.encode("utf-8"))) for key in keys]

    def delete(self, path):
        with self._guard:
            self.store.pop(path, None)

    def delete_prefix(self, prefix):
        with self._guard:
            for key in [k for k in list(self.store) if k.startswith(prefix)]:
                del self.store[key]

    def lock(self, name, ttl=None):
        self.lock_names.append(name)
        with self._guard:
            return self._locks.setdefault(name, threading.Lock())


def _mgr():
    mgr = IdentityManager.__new__(IdentityManager)
    mgr.client = FakeClient()
    return mgr


def _raw(mgr, path):
    value, _ = mgr.client.get(path)
    assert value is not None, f"expected a stored document at {path}"
    return value.decode("utf-8")


def _doc(mgr, path):
    return json.loads(_raw(mgr, path))


# --- Framework-defaults fakes / autouse isolation -----------------------------

class _FrameworkConfig:
    """Stand-in for ``IdentityManager`` serving framework-wide guardrail rules."""

    def __init__(self, rules=None, raises=False):
        self.rules = rules if rules is not None else {}
        self.raises = raises
        self.calls = 0

    def get_guardrails_defaults(self):
        self.calls += 1
        if self.raises:
            raise RuntimeError("etcd is down")
        return self.rules


@pytest.fixture(autouse=True)
def _fresh_framework_defaults(monkeypatch):
    """No test may read real etcd, and no cached rules may leak between tests."""
    guardrails.reset_framework_guardrails_cache()
    fake = _FrameworkConfig({})
    monkeypatch.setattr(auth, "get_identity_manager", lambda: fake)
    yield fake
    guardrails.reset_framework_guardrails_cache()


def _pin_framework(monkeypatch, rules):
    fake = _FrameworkConfig(rules)
    monkeypatch.setattr(auth, "get_identity_manager", lambda: fake)
    guardrails.reset_framework_guardrails_cache()
    return fake


def _pattern_rule(name="deny", patterns=("SECRET",), action="block"):
    return {"name": name, "type": "deny_patterns", "patterns": list(patterns), "action": action}


# --- 1. Input patterns: block / redact ---------------------------------------

def test_input_block_returns_allow_shape_and_bounded_preview():
    rule = _pattern_rule("secret-block", ["SECRET-[0-9]+"])
    prompt = "please leak SECRET-123 now"

    action, text, hits = guardrails.evaluate_input(prompt, [rule])

    assert action == "block"
    assert text == prompt
    assert len(hits) == 1
    assert hits[0] == {
        "rule": "secret-block",
        "type": "deny_patterns",
        "preview": "SECRET-123",
    }

    # The preview is bounded to 120 chars even for a very long match.
    _, _, long_hits = guardrails.evaluate_input("A" * 500, [_pattern_rule("long", ["A+"])])
    assert len(long_hits[0]["preview"]) <= guardrails.MAX_PREVIEW_CHARS
    assert len(long_hits[0]["preview"]) == guardrails.MAX_PREVIEW_CHARS


def test_input_non_matching_pattern_allows_untouched_text():
    rule = _pattern_rule("secret-block", ["SECRET"])

    assert guardrails.evaluate_input("nothing to see", [rule]) == ("allow", "nothing to see", [])


def test_input_redact_replaces_every_match():
    rule = _pattern_rule("token-redact", ["TOKEN[0-9]+"], action="redact")

    action, text, hits = guardrails.evaluate_input("TOKEN1 and TOKEN2", [rule])

    assert action == "redact"
    assert text == f"{guardrails.REDACTION_MARKER} and {guardrails.REDACTION_MARKER}"
    assert len(hits) == 1
    assert hits[0]["rule"] == "token-redact"
    assert hits[0]["preview"] == "TOKEN1"


def test_input_rule_order_redact_then_block_evaluates_redacted_text():
    redact = _pattern_rule("token-redact", ["TOKEN[0-9]+"], action="redact")
    block = _pattern_rule("token-block", ["TOKEN"])

    # Redact first: the later block rule sees only the marker, so nothing blocks.
    action, text, hits = guardrails.evaluate_input("TOKEN7", [redact, block])
    assert action == "redact"
    assert text == guardrails.REDACTION_MARKER
    assert [hit["rule"] for hit in hits] == ["token-redact"]

    # Block first: it short-circuits before the redactor rewrites anything.
    action, text, hits = guardrails.evaluate_input("TOKEN7", [block, redact])
    assert action == "block"
    assert text == "TOKEN7"
    assert [hit["rule"] for hit in hits] == ["token-block"]


# --- 2. Output patterns: block / redact / no-op ------------------------------

def test_output_block_and_redact():
    prompt = "output with SECRET-42 inside"

    action, text, hits = guardrails.evaluate_output(prompt, [_pattern_rule("out-deny", ["SECRET-[0-9]+"])])
    assert action == "block"
    assert text == prompt
    assert hits[0]["preview"] == "SECRET-42"

    action, text, hits = guardrails.evaluate_output(
        "SECRET-1 then SECRET-2", [_pattern_rule("out-redact", ["SECRET-[0-9]+"], action="redact")])
    assert action == "redact"
    assert text == f"{guardrails.REDACTION_MARKER} then {guardrails.REDACTION_MARKER}"
    assert hits[0]["preview"] == "SECRET-1"


def test_output_without_rules_returns_the_same_string():
    text = "untouched output"

    action, checked, hits = guardrails.evaluate_output(text, [])

    assert action == "allow"
    assert checked is text
    assert hits == []


# --- 3. max_chars -------------------------------------------------------------

def test_input_max_chars_blocks_over_limit_and_allows_at_or_under():
    rule = {"name": "input-limit", "type": "max_chars", "value": 5}

    action, text, hits = guardrails.evaluate_input("abcdefghij", [rule])
    assert action == "block"
    assert text == "abcdefghij"
    assert hits[0] == {"rule": "input-limit", "type": "max_chars", "preview": "10>5"}

    assert guardrails.evaluate_input("abcde", [rule]) == ("allow", "abcde", [])
    assert guardrails.evaluate_input("abc", [rule]) == ("allow", "abc", [])


def test_output_max_chars_truncates_with_marker_and_allows_under_limit():
    rule = {"name": "output-limit", "type": "max_chars", "value": 4}

    action, text, hits = guardrails.evaluate_output("abcdefghij", [rule])
    assert action == "redact"
    assert text == "abcd… [truncated 6 chars]"
    assert hits[0]["rule"] == "output-limit"
    assert hits[0]["preview"] == "10>4"

    action, text, hits = guardrails.evaluate_output("abcd", [rule])
    assert action == "allow"
    assert text == "abcd"
    assert hits == []


# --- 4. Fail-open on malformed rules -----------------------------------------

def test_invalid_regex_skips_that_rule_but_evaluates_the_rest():
    bad = {"name": "bad-regex", "type": "deny_patterns", "patterns": ["(unclosed"], "action": "block"}
    good = _pattern_rule("good-regex")

    assert guardrails.evaluate_input("SECRET", [bad]) == ("allow", "SECRET", [])

    action, text, hits = guardrails.evaluate_input("SECRET", [bad, good])
    assert action == "block"
    assert [hit["rule"] for hit in hits] == ["good-regex"]


@pytest.mark.parametrize("malformed", [
    "not-a-rule",
    42,
    None,
    {"name": "unknown-type", "type": "does_not_exist"},
    {"name": "patterns-not-a-list", "type": "deny_patterns", "patterns": 123},
    {"name": "patterns-not-strings", "type": "deny_patterns", "patterns": [1, "SECRET"]},
    {"name": "max-chars-string", "type": "max_chars", "value": "10"},
    {"name": "max-chars-bool", "type": "max_chars", "value": True},
    {"name": "max-chars-negative", "type": "max_chars", "value": -1},
    {"name": "unknown-action", "type": "deny_patterns", "patterns": ["SECRET"], "action": "nuke"},
    {"name": "non-string-action", "type": "deny_patterns", "patterns": ["SECRET"], "action": True},
])
def test_malformed_rules_are_skipped_fail_open(malformed):
    # Alone, a malformed rule is a no-op (and never raises).
    assert guardrails.evaluate_input("SECRET", [malformed]) == ("allow", "SECRET", [])

    # A later valid rule still runs.
    action, _, hits = guardrails.evaluate_input("SECRET", [malformed, _pattern_rule("good")])
    assert action == "block"
    assert [hit["rule"] for hit in hits] == ["good"]


def test_rule_container_that_is_not_a_list_is_fail_open():
    assert guardrails.evaluate_input("SECRET", {"type": "deny_patterns"}) == ("allow", "SECRET", [])


def test_pathological_nesting_is_skipped_like_any_other_malformed_pattern():
    deep = {"name": "deep-regex", "type": "deny_patterns", "patterns": ["(" * 50000]}

    action, text, hits = guardrails.evaluate_input("SECRET", [deep, _pattern_rule("good")])

    assert action == "block"
    assert text == "SECRET"
    assert [hit["rule"] for hit in hits] == ["good"]


# --- 5. Merge semantics -------------------------------------------------------

def _names(rules):
    return [rule.get("name") for rule in rules]


def test_merge_rules_puts_framework_first_then_agent_per_direction():
    framework = {
        "on_input": [_pattern_rule("fw-in")],
        "on_output": [_pattern_rule("fw-out")],
    }
    agent = {
        "guardrails": {
            "on_input": [_pattern_rule("agent-in")],
            "on_output": [_pattern_rule("agent-out")],
        }
    }

    merged = guardrails.merge_rules(agent, framework)

    assert _names(merged["on_input"]) == ["fw-in", "agent-in"]
    assert _names(merged["on_output"]) == ["fw-out", "agent-out"]


def test_merge_rules_accepts_nested_and_top_level_shapes():
    nested_agent = {"guardrails": {"on_input": [_pattern_rule("nested-in")]}}
    flat_agent = {"on_input": [_pattern_rule("flat-in")]}
    nested_framework = {"guardrails": {"on_input": [_pattern_rule("nested-fw")]}}
    flat_framework = {"on_input": [_pattern_rule("flat-fw")]}

    assert _names(guardrails.merge_rules(nested_agent, {})["on_input"]) == ["nested-in"]
    assert _names(guardrails.merge_rules(flat_agent, {})["on_input"]) == ["flat-in"]
    assert _names(guardrails.merge_rules({"on_input": [_pattern_rule("agent-in")]}, nested_framework)["on_input"]) == [
        "nested-fw", "agent-in",
    ]
    assert _names(guardrails.merge_rules({"on_input": [_pattern_rule("agent-in")]}, flat_framework)["on_input"]) == [
        "flat-fw", "agent-in",
    ]


def test_merge_rules_with_explicit_empty_defaults_never_reads_etcd(monkeypatch):
    class _ExplodingManager:
        def get_guardrails_defaults(self):  # pragma: no cover - the assert is the test
            raise AssertionError("merge_rules must not read framework defaults when given {}")

    monkeypatch.setattr(auth, "get_identity_manager", lambda: _ExplodingManager())

    merged = guardrails.merge_rules({"guardrails": {"on_input": [_pattern_rule("agent-in")]}}, {})

    assert _names(merged["on_input"]) == ["agent-in"]
    assert merged["on_output"] == []


def test_agent_rule_cannot_shadow_a_framework_block(monkeypatch):
    _pin_framework(monkeypatch, {"on_input": [_pattern_rule("framework-block", ["SECRET"])]})
    agent_config = {"guardrails": {"on_input": [_pattern_rule("agent-redact", ["SECRET"], action="redact")]}}

    action, text, hits = guardrails.evaluate_agent_input("a SECRET b", agent_config)

    assert action == "block"
    assert text == "a SECRET b"
    assert [hit["rule"] for hit in hits] == ["framework-block"]


# --- 6. Framework-defaults cache ---------------------------------------------

def test_framework_cache_one_read_within_ttl_and_refresh_after_reset(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(guardrails, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    fake = _pin_framework(monkeypatch, {"on_input": [_pattern_rule("fw-in")]})

    first = guardrails.get_framework_guardrails()
    second = guardrails.get_framework_guardrails()

    assert fake.calls == 1
    assert second is first
    assert _names(first["on_input"]) == ["fw-in"]

    guardrails.reset_framework_guardrails_cache()
    third = guardrails.get_framework_guardrails()
    assert fake.calls == 2
    assert third == first

    # Past the TTL the cache is refreshed too (no sleep: fake clock).
    clock[0] += guardrails.FRAMEWORK_CACHE_TTL_SECONDS + 1
    guardrails.get_framework_guardrails()
    assert fake.calls == 3


def test_framework_cache_serves_stale_rules_when_the_read_fails(monkeypatch):
    clock = [2000.0]
    monkeypatch.setattr(guardrails, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    fake = _pin_framework(monkeypatch, {"on_output": [_pattern_rule("fw-out")]})

    warm = guardrails.get_framework_guardrails()
    assert fake.calls == 1

    clock[0] += guardrails.FRAMEWORK_CACHE_TTL_SECONDS + 1
    fake.raises = True

    stale = guardrails.get_framework_guardrails()  # must not raise

    assert fake.calls == 2
    assert stale == warm
    assert _names(stale["on_output"]) == ["fw-out"]


# --- 7. Hit counting ----------------------------------------------------------

def test_hit_counts_aggregates_per_rule_name():
    hits = [
        {"rule": "a", "type": "deny_patterns", "preview": "x"},
        {"rule": "a", "type": "deny_patterns", "preview": "y"},
        {"rule": "b", "type": "max_chars", "preview": "10>5"},
        {"rule": ""},
        {"rule": None},
        {},
        "not-a-dict",
    ]

    assert guardrails.hit_counts(hits) == {"a": 2, "b": 1}
    assert guardrails.hit_counts([]) == {}
    assert guardrails.hit_counts(None) == {}


def test_record_guardrail_hits_accumulates_in_the_agent_metrics_doc():
    mgr = _mgr()

    mgr.record_guardrail_hits("hit-agent", {"secret-block": 1})
    mgr.record_guardrail_hits("hit-agent", {"secret-block": 2, "too-long": 1})

    assert _doc(mgr, "/metrics/agents/hit-agent")["guardrail_hits"] == {
        "secret-block": 3,
        "too-long": 1,
    }
    summary = mgr.get_agent_latency("hit-agent")
    assert summary["guardrail_hits"] == {"secret-block": 3, "too-long": 1}
    assert summary["count"] == 0
    # Provider docs never carry per-rule counters.
    assert mgr.get_provider_latency("google")["guardrail_hits"] == {}


def test_record_guardrail_hits_ignores_empty_and_malformed_input():
    mgr = _mgr()

    mgr.record_guardrail_hits("other-agent", {})
    mgr.record_guardrail_hits("", {"x": 1})
    mgr.record_guardrail_hits("other-agent", {"bad": "many", "": 1})
    assert not [key for key in mgr.client.store if key.startswith("/metrics/")]

    mgr.record_guardrail_hits("other-agent", {"good": 2})
    assert _doc(mgr, "/metrics/agents/other-agent") == {"guardrail_hits": {"good": 2}}


# --- 8. Background runs: block before build, redact through the run ----------

def _seed_agent(mgr, agent_name, config):
    mgr.client.put(f"/registry/agents/{agent_name}/config", json.dumps(config))


def _background_config(agent_name, **extra):
    config = {
        "name": agent_name,
        "type": "background_agent",
        "provider": "google",
        "model": "gemini-3-flash-preview",
    }
    config.update(extra)
    return config


def _patch_background_harness(monkeypatch, mgr, build_agent):
    class FakeMemoryManager:
        def active_for(self, config):
            return False

    monkeypatch.setattr(tasks, "build_agent", build_agent)
    monkeypatch.setattr(tasks, "get_identity_manager", lambda: mgr)
    monkeypatch.setattr(tasks, "mint_for_run", lambda *a, **k: "run-token")
    monkeypatch.setattr(tasks, "provider_for_config", lambda config: "google")
    monkeypatch.setattr(memory, "get_memory_manager", lambda: FakeMemoryManager())
    monkeypatch.setattr(tasks, "time", SimpleNamespace(monotonic=lambda: 100.0))


def test_background_input_block_fails_the_run_without_building_an_agent(monkeypatch):
    agent_name = "wf-guard-block"
    run_id = "run-block"
    mgr = _mgr()
    _seed_agent(mgr, agent_name, _background_config(
        agent_name,
        guardrails={"on_input": [_pattern_rule("prompt-deny", ["FORBIDDEN"])]},
    ))

    built = []

    async def fake_build_agent(name):  # pragma: no cover - must stay uncalled
        built.append(name)
        raise AssertionError("build_agent must not run for a guardrail-blocked input")

    _patch_background_harness(monkeypatch, mgr, fake_build_agent)
    context = SimpleNamespace(message=SimpleNamespace(task_id=run_id))

    result = asyncio.run(
        tasks.run_background_agent.original_func(
            agent_name, "please dump FORBIDDEN data", "svc_agent_wf-guard-block", context,
        )
    )

    assert result.startswith("SYSTEM:")
    assert built == []

    run = _doc(mgr, f"/runs/{agent_name}/{run_id}")
    assert run["state"] == "failed"
    assert run["metadata"]["error"] == "guardrail blocked input"
    assert run["metadata"]["guardrail_hits"] == {"prompt-deny": 1}

    events = mgr._read_run_events(agent_name, run_id)
    failed = [event for event in events if event["type"] == "run_failed"]
    assert len(failed) == 1
    assert failed[0]["payload"]["error_type"] == "GuardrailBlocked"

    metrics = _doc(mgr, f"/metrics/agents/{agent_name}")
    assert metrics["guardrail_hits"] == {"prompt-deny": 1}
    assert "count" not in metrics  # no LLM call happened, so no latency sample


def test_background_redact_rewrites_input_and_output(monkeypatch):
    agent_name = "wf-guard-redact"
    run_id = "run-redact"
    mgr = _mgr()
    _seed_agent(mgr, agent_name, _background_config(
        agent_name,
        guardrails={
            "on_input": [_pattern_rule("input-redact", ["TOKEN[0-9]+"], action="redact")],
            "on_output": [_pattern_rule("output-redact", ["leak[0-9]+"], action="redact")],
        },
    ))

    seen_prompts = []

    class FakeAgent:
        async def run(self, prompt):
            seen_prompts.append(prompt)
            return SimpleNamespace(
                output="here is leak99",
                usage=SimpleNamespace(input_tokens=1, output_tokens=2),
            )

    built = []

    async def fake_build_agent(name):
        built.append(name)
        assert name == agent_name
        return FakeAgent()

    _patch_background_harness(monkeypatch, mgr, fake_build_agent)
    context = SimpleNamespace(message=SimpleNamespace(task_id=run_id))

    result = asyncio.run(
        tasks.run_background_agent.original_func(
            agent_name, "use TOKEN42 now", "svc_agent_wf-guard-redact", context,
        )
    )

    assert built == [agent_name]
    assert seen_prompts == ["use [REDACTED] now"]
    assert result == "here is [REDACTED]"

    run = _doc(mgr, f"/runs/{agent_name}/{run_id}")
    assert run["state"] == "completed"
    assert run["metadata"]["prompt"] == "use [REDACTED] now"
    assert run["metadata"]["output"] == "here is [REDACTED]"
    assert _doc(mgr, f"/metrics/agents/{agent_name}")["guardrail_hits"] == {
        "input-redact": 1,
        "output-redact": 1,
    }


# --- 9. No rules configured ⇒ exact no-op ------------------------------------

def test_no_rules_returns_the_same_text_and_writes_no_metrics(monkeypatch):
    class _NoWriteManager:
        def __init__(self):
            self.writes = []
            self.reads = 0

        def get_guardrails_defaults(self):
            self.reads += 1
            return {}

        def record_guardrail_hits(self, *args, **kwargs):
            self.writes.append((args, kwargs))

        def record_agent_latency(self, *args, **kwargs):
            self.writes.append((args, kwargs))

    fake = _NoWriteManager()
    monkeypatch.setattr(auth, "get_identity_manager", lambda: fake)

    prompt = "plain prompt"
    output = "plain output"

    input_action, checked_input, input_hits = guardrails.evaluate_agent_input(prompt, {"name": "no-rules"})
    output_action, checked_output, output_hits = guardrails.evaluate_agent_output(output, {})

    assert (input_action, input_hits) == ("allow", [])
    assert checked_input is prompt
    assert (output_action, output_hits) == ("allow", [])
    assert checked_output is output
    assert fake.writes == []
    assert fake.reads == 1  # one cached framework read, no metrics traffic


# --- 10. Host route paths -----------------------------------------------------

def _host_request(model, content):
    return host.ChatRequest(model=model, messages=[host.ChatMessage(role="user", content=content)])


def _discard_background(coro, name):
    """Close spawned coroutines so no task outlives the single asyncio.run()."""
    coro.close()


def _patch_host_agent(monkeypatch, agent_name, config):
    monkeypatch.setattr(host.identity_mgr, "get_disabled_standard_agents", lambda: [])
    monkeypatch.setattr(host.identity_mgr, "get_agent_config", lambda name: config)
    monkeypatch.setattr(host.identity_mgr, "record_guardrail_hits", lambda *a, **k: None)
    monkeypatch.setattr(host.identity_mgr, "record_usage", lambda *a, **k: None)
    monkeypatch.setattr(host.identity_mgr, "record_agent_usage", lambda *a, **k: None)
    monkeypatch.setattr(host.health_monitor, "get_status", lambda *a, **k: {"status": "Online"})
    monkeypatch.setattr(host.health_monitor, "record_event", lambda *a, **k: None)
    monkeypatch.setattr(host, "_spawn_background", _discard_background)
    monkeypatch.setattr(host, "get_memory_manager", lambda: SimpleNamespace(active_for=lambda cfg: False))


def test_host_input_block_returns_400_with_rule_name_but_no_preview(monkeypatch):
    agent_name = "guard-host-input"
    config = {
        "name": agent_name,
        "type": "user_agent",
        "external": True,
        "provider": "google",
        "model": "gemini-3-flash-preview",
        "guardrails": {"on_input": [_pattern_rule("no-secrets", ["TOPSECRET"])]},
    }
    _patch_host_agent(monkeypatch, agent_name, config)

    class FakeAgent:
        async def run(self, *a, **k):  # pragma: no cover - must stay uncalled
            raise AssertionError("agent.run must not run for a blocked input")

    async def fake_get_agent(name):
        return FakeAgent()

    monkeypatch.setattr(host, "get_agent", fake_get_agent)

    with pytest.raises(host.HTTPException) as exc_info:
        asyncio.run(host.chat_completions(_host_request(agent_name, "my TOPSECRET value")))

    assert exc_info.value.status_code == 400
    assert "no-secrets" in exc_info.value.detail
    # Rule names only: the matched payload never leaks back to the caller.
    assert "TOPSECRET" not in exc_info.value.detail


def test_host_output_block_replaces_the_response_with_the_system_notice(monkeypatch):
    agent_name = "guard-host-output"
    config = {
        "name": agent_name,
        "type": "user_agent",
        "external": True,
        "provider": "google",
        "model": "gemini-3-flash-preview",
        "guardrails": {"on_output": [_pattern_rule("classified", ["CLASSIFIED"])]},
    }
    _patch_host_agent(monkeypatch, agent_name, config)

    class FakeResult:
        output = "the CLASSIFIED plan"
        usage = None

    class FakeAgent:
        async def run(self, *a, **k):
            return FakeResult()

    async def fake_get_agent(name):
        return FakeAgent()

    monkeypatch.setattr(host, "get_agent", fake_get_agent)

    response = asyncio.run(host.chat_completions(_host_request(agent_name, "what is the plan?")))

    content = response["choices"][0]["message"]["content"]
    assert content == "SYSTEM: Response blocked by guardrail policy. The agent output was withheld."
    assert "CLASSIFIED" not in content


def test_framework_mixed_nested_and_top_level_shapes_keep_every_direction():
    # A nested block for one direction must not drop a top-level rule for the other.
    raw = {
        "guardrails": {"on_input": [_pattern_rule("fw-in")]},
        "on_output": [_pattern_rule("fw-out")],
    }
    normalized = guardrails._normalize_framework(raw)

    assert _names(normalized["on_input"]) == ["fw-in"]
    assert _names(normalized["on_output"]) == ["fw-out"]


def test_empty_nested_block_does_not_shadow_top_level_rules():
    raw = {"guardrails": {"on_input": []}, "on_input": [_pattern_rule("fw-in")]}

    assert _names(guardrails.merge_rules(raw, {})["on_input"]) == ["fw-in"]


def test_stacked_max_chars_reports_total_dropped_from_the_original():
    rules = [
        {"type": "max_chars", "name": "wide", "value": 100},
        {"type": "max_chars", "name": "narrow", "value": 40},
    ]
    action, text, hits = guardrails.evaluate_output("x" * 1000, rules)

    assert action == "redact"
    assert text.endswith("[truncated 960 chars]")
    assert text.startswith("x" * 40)
    assert [hit["rule"] for hit in hits] == ["wide", "narrow"]


def test_decisions_are_logged_with_bounded_previews(caplog):
    rule = _pattern_rule("secret", patterns=["SECRET-[0-9]+"])

    with caplog.at_level("INFO", logger="core.guardrails"):
        action, _, _ = guardrails.evaluate_input("my SECRET-123 value", [rule])

    assert action == "block"
    assert "decision=block" in caplog.text
    assert "SECRET-123" in caplog.text


def test_host_redacts_every_message_and_block_covers_earlier_turns(monkeypatch):
    agent_name = "guard-host-history"
    config = {
        "name": agent_name,
        "type": "user_agent",
        "external": True,
        "provider": "google",
        "model": "gemini-3-flash-preview",
        "guardrails": {
            "on_input": [_pattern_rule("token", ["TOKEN[0-9]+"], action="redact")],
        },
    }
    _patch_host_agent(monkeypatch, agent_name, config)
    seen = {}

    class FakeAgent:
        async def run(self, prompt, message_history=None, deps=None):
            seen["prompt"] = prompt
            seen["history"] = [part.content for msg in message_history or [] for part in msg.parts]
            result = SimpleNamespace(output="ok", usage=None)
            return result

    async def fake_get_agent(name):
        return FakeAgent()

    monkeypatch.setattr(host, "get_agent", fake_get_agent)
    request = host.ChatRequest(model=agent_name, messages=[
        host.ChatMessage(role="user", content="my TOKEN123"),
        host.ChatMessage(role="assistant", content="noted"),
        host.ChatMessage(role="user", content="what was it?"),
    ])

    response = asyncio.run(host.chat_completions(request))

    assert response["choices"][0]["message"]["content"] == "ok"
    assert seen["prompt"] == "what was it?"
    assert "my [REDACTED]" in seen["history"]

    # A block rule on an earlier turn still refuses the whole request.
    config["guardrails"]["on_input"] = [_pattern_rule("token", ["TOKEN[0-9]+"], action="block")]
    request = host.ChatRequest(model=agent_name, messages=[
        host.ChatMessage(role="user", content="my TOKEN123"),
        host.ChatMessage(role="user", content="benign"),
    ])
    with pytest.raises(host.HTTPException) as excinfo:
        asyncio.run(host.chat_completions(request))
    assert excinfo.value.status_code == 400
    assert "token" in excinfo.value.detail
    assert "TOKEN123" not in excinfo.value.detail
