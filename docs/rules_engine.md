# Trellis Rules Engine: Deterministic Routing

The Rules Engine is a deterministic, declarative policy layer that runs **before** vector semantic
search in `core/agent_search.py:search_agents()`. It lets you lock specific queries onto a specific
agent using plain-language rules instead of relying on embedding similarity, which can drift or
misroute when agent descriptions share vocabulary.

Both consumers of `search_agents()` — the Gateway MCP tool (`core/gateway.py`) and the Supervisor's
internal discovery tool (`core/agent_factory.py`) — automatically inherit rule-based routing with no
call-site changes; the engine is wired once, centrally, in `core/agent_search.py`.

---

## How It Fits Into Search

```
query → readiness gating → rules engine (LLM structured decider) → confidence >= 0.8?
                                                                        │
                                                        YES ───────────┤──────────── NO / no match / timeout
                                                         │                                    │
                                                 short-circuit:                     falls through to
                                                 return locked agent                vector semantic search
                                                 (embedding call skipped)           (existing behavior)
```

- **Rule precedence**: if an eligible rule locks onto an agent with confidence `>= 0.8`, that agent
  is returned immediately — the Gemini embedding call for that query is skipped entirely.
- **Fail-open by design**: any failure evaluating rules (timeout, API error, missing key, malformed
  eligibility data) is logged as a warning and falls through to the existing vector search. Rule
  evaluation can never crash or block a search request.
- **No priority numbers**: there is no `priority: int` field anywhere. Specificity is expressed only
  through `use_when` / `do_not_use_when` natural-language conditions — see [Writing Good Rules](#writing-good-rules).

---

## Authoring Agent-Level Rules

Add a `rules:` list to an agent's `workspace/agents/<name>/config.yaml`. This is the right place for
rules that are intrinsic to what the agent does — no other agent needs to know about them.

```yaml
rules:
  - description: "Acme troubleshooting service, packet captures, and flow-level network drops"
    use_when:
      - "User requests packet capture (PCAP) inspection or troubleshooting session diagnostics"
      - "User asks to investigate packet drops, flow anomalies, or interface resets on Acme connectors"
    do_not_use_when:
      - "User is asking for an executive ticket summary or customer-facing status update"
      - "User is inquiring about billing, licenses, or tenant provisioning"
    examples:
      - "Why are packets dropping on connector CX-102?"
      - "Analyze the PCAP trace from Acme troubleshooting session 948"
```

An agent may declare multiple entries in `rules:` if it covers more than one distinct routing
scenario; each entry is evaluated independently against the query.

### Field reference (`AgentRule`, `core/models.py`)

| Field | Required | Purpose |
| :--- | :--- | :--- |
| `description` | No | One-line summary shown to the LLM decider for context. Not itself matched against. |
| `use_when` | No (default `[]`) | Positive conditions under which this agent **must** be selected. Write as conditions about the query/intent, not keywords. |
| `do_not_use_when` | No (default `[]`) | Negative boundaries that **disqualify** this agent even if `use_when` also matches. Always wins over `use_when`. |
| `examples` | No (default `[]`) | Representative real user queries. Helps the LLM decider generalize beyond the literal wording of `use_when`. |

> ⚠️ These models do not set `extra="forbid"` (consistent with the rest of `core/models.py`'s config
> loading). A typo'd key — e.g. `when_to_use` instead of `use_when` — is **silently dropped**, not
> rejected. It will not raise a validation error; it will just produce a rule with an empty condition
> list that never matches anything. Stick to the exact field names above.

A rule block with all fields empty (`use_when: []`, `do_not_use_when: []`, `examples: []`) is still
schema-valid but functionally inert — it will never influence the LLM decider's output.

---

## Authoring Global Overrides

Cross-agent dispute resolution and organization-wide policy belongs in the optional
`workspace/routing_rules.yaml`, not in any single agent's config. Use this when two or more agents'
rules could plausibly both match the same query and you need to declare a winner.

```yaml
version: "1.0"
global_rules:
  - rule_id: "override-acme-infrastructure-troubleshooting"
    target_agent: "troubleshooting-agent"
    description: "Acme core networking data plane issues take strict precedence over generic ticket summary"
    use_when:
      - "Query involves deep-dive data plane troubleshooting, routing flaps, or connector packet loss"
    do_not_use_when:
      - "User explicitly asks to draft or summarize an end-of-day customer ticket report"
    examples:
      - "Triage BGP route flapping on Acme connector CX-405"
```

**Global rules always take strict precedence over agent-level rules** during LLM evaluation — see
`EVALUATION PRINCIPLES` in the compiled prompt (`core/rules_engine.py:compile_rules_prompt`).

### Field reference (`GlobalRule`, `core/models.py`)

| Field | Required | Purpose |
| :--- | :--- | :--- |
| `rule_id` | **Yes** | Unique identifier, e.g. `override-pcap-triage`. Used only for logging/traceability, not matched against. |
| `target_agent` | **Yes** | Exact agent `name` this override locks onto. **Must match a real, currently-eligible agent** — see the caveat below. |
| `description` | No | Operational justification, shown to the LLM decider. |
| `use_when` / `do_not_use_when` / `examples` | No | Same semantics as `AgentRule` above. |

> ⚠️ There is no cross-validation today that `target_agent` names a real agent. A typo'd
> `target_agent` (e.g. `troubleshoting-agent`) will sync to etcd successfully and simply never match
> anything at evaluation time — the LLM is instructed to only choose from the eligible agent pool, so
> a global rule targeting a nonexistent or currently-ineligible agent is silently inert, not an error.
> Double-check `target_agent` spelling against the agent's `name:` field in its `config.yaml`.

If `workspace/routing_rules.yaml` does not exist, the sync script logs
`No workspace/routing_rules.yaml found, skipping.` and the rules engine simply has zero global rules
— agent-level rules still work fine on their own.

---

## Writing Good Rules

1. **Write conditions about intent, not keywords.** `use_when` and `do_not_use_when` are read by an
   LLM, not pattern-matched — write them the way you'd explain the boundary to a new team member
   ("user wants a customer-facing recap"), not as a list of trigger words.
2. **Use `do_not_use_when` for the actual disambiguation work.** Two agents' descriptions overlapping
   on vocabulary (e.g. both mention "Acme", "case", "connector") is exactly the semantic-drift
   problem this engine exists to solve — spell out the boundary explicitly rather than hoping
   `use_when` alone is specific enough.
3. **`do_not_use_when` always wins.** If a query satisfies both a `use_when` condition and a
   `do_not_use_when` condition on the same rule, the agent is disqualified. Don't rely on `use_when`
   phrasing to implicitly exclude an edge case — state the exclusion directly.
4. **Add real examples, not paraphrases of `use_when`.** Examples should read like something a user
   actually typed. They help the LLM decider generalize to phrasing you didn't anticipate.
5. **Only claim high confidence for unambiguous queries.** The decider is instructed to return
   `matched_agent: null` (with low confidence) for anything general, ambiguous, or spanning multiple
   domains without an explicit global override — this is intentional, not a bug. If a query should
   always resolve deterministically, that's a signal you need a **global override** with a tight
   `use_when`/`do_not_use_when`, not a looser agent-level rule.
6. **Prefer a few precise rules over many overlapping ones.** Each additional rule adds tokens to the
   compiled prompt (see [Performance](#performance--operational-notes) below) and more surface area
   for LLM ambiguity between your own agent's rules.
7. **Escaping**: avoid literal double-quote characters inside `use_when` / `do_not_use_when` /
   `examples` strings (e.g. pasting a quoted chat log verbatim) — the compiled prompt renders these
   as `* "text"`, and an embedded `"` will render with unescaped nested quotes. Harmless for the LLM's
   comprehension, but keep strings clean for readability in logs.

---

## Readiness Gating

Only **eligible** agents' rules are ever compiled into the LLM decider's prompt. An agent's rules are
**excluded** from evaluation entirely if any of the following is true (`core/rules_engine.py:filter_eligible_agents`):

- The agent is `supervisor` (the router itself is never a routing target).
- `type` is `background_agent` or `background_script`.
- `external: false` is set (internal-only worker subagents are never surfaced to query routing).
- The agent is in the disabled-agents set.
- The agent's health status is `Offline`.
- The agent is **unconfigured** — missing a required secret or variable.
- The agent has an empty `rules:` list (nothing to evaluate).

This prevents "black hole" routing, where a query would deterministically lock onto an agent that
can't actually serve the request. Access-group / OIDC filtering is explicitly **out of scope** for
this gating — it is not consulted here.

If **no** eligible agent has rules and **no** global rules exist, the rules engine is skipped
entirely (`has_active_rules()` returns `False`) — the query goes straight to vector semantic search
with zero added latency, exactly as it did before this feature existed.

---

## Confidence Threshold & Fail-Open Behavior

The evaluator is a single-pass structured LLM call (Gemini Flash, thinking budget `0` for low
latency) that returns a `RuleEvaluationResult` (`matched_agent`, `confidence`, `reasoning`). A match
is only honored — and the vector search skipped — when **all** of these hold:

- `matched_agent` is non-null.
- `matched_agent` names an agent currently in the eligible pool (not hallucinated, not since gone
  ineligible).
- `confidence >= RULES_CONFIDENCE_THRESHOLD` (default `0.8`).

Any other outcome — including every failure mode below — collapses to "no rule match" and the search
proceeds through the existing vector/keyword fallback, unchanged:

| Situation | Behavior |
| :--- | :--- |
| No rule clearly matches | `matched_agent: null` returned by the LLM — expected/common, logged at debug level. |
| Confidence below threshold | Falls open — logged at debug level. |
| LLM names an ineligible/unknown agent | Falls open — logged as a **warning** (possible hallucination or stale rule). |
| LLM call times out (`RULES_EVALUATION_TIMEOUT`, default 2.5s) | Falls open — logged as a **warning**. |
| LLM API error, rate limit, missing API key | Falls open — logged as a **warning**. |
| Error resolving agent eligibility (etcd/discovery failure) | Falls open — logged as a **warning**. |

Environment variables (`core/rules_engine.py`):

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `RULES_CONFIDENCE_THRESHOLD` | `0.8` | Minimum confidence to honor a rule lock. |
| `RULES_EVALUATION_TIMEOUT` | `2.5` (seconds) | Hard timeout on the LLM call before failing open. |
| `RULES_EVALUATION_MODEL` | `gemini-2.5-flash` | Model used for the structured decider. |

Identical queries are memoized in-process for 60 seconds (keyed on the query text **and** a hash of
the current rule catalog, so an edited rule invalidates the cache immediately even within the TTL
window) — repeated identical queries do not re-invoke the LLM.

---

## Syncing Rules to the Registry

Rules are only read from `workspace/*.yaml` at authoring time. Push changes to etcd with:

```bash
python scripts/sync_to_db.py
```

Expected output includes:

```
Saved config for agent: troubleshooting-agent (Type: user_agent, with 1 rules)
Saved routing rules from workspace/routing_rules.yaml (2 global rules)
```

A malformed `workspace/routing_rules.yaml` (fails `RoutingRulesConfig` validation) prints a
`WARNING: invalid workspace/routing_rules.yaml, skipping:` line and leaves whatever was previously
synced untouched — it does not abort the rest of the sync run. Malformed rules inside a single
agent's `config.yaml` are similarly dropped to `[]` for that agent only, with a warning, rather than
failing the whole sync.

Changes take effect on the next request — no restart required, same as any other agent config
change (see `docs/agents.md`).

---

## Verifying Rule Behavior End-to-End

1. **Deterministic lock**: call `search_agents(query="Analyze the PCAP trace from Acme
   troubleshooting session 948")`. Look for
   `[RulesEngine] Matched rule for agent: troubleshooting-agent (confidence: 0.9...)` in the logs;
   `troubleshooting-agent` should be the only/first result and the Gemini embedding API should not be
   called for that query.
2. **Negative boundary**: call `search_agents(query="Fetch executive ticket summary for Acme
   connector CX-102")`. Even though it mentions a connector, the `troubleshooting-agent` rule's
   `do_not_use_when: executive ticket summary` should disqualify it, and the query should resolve to
   `ticket-summary-agent` or fall through to semantic ranking.
3. **Fail-open resilience**: set `RULES_EVALUATION_TIMEOUT=0.001` and repeat query 1. Expect
   `[RulesEngine] Evaluation timed out after 0.001s; failing open to semantic search`, and a normal,
   successful vector-search result with no error surfaced to the caller.
4. **Readiness gating**: disable `troubleshooting-agent` (or revoke a required secret) and repeat
   query 1. Its rules must not be evaluated at all — the query should fall through to remaining
   eligible agents.

Grep targets when debugging in production:

- `[RulesEngine] Matched rule for agent: ...` — a rule lock fired (info level).
- `[RulesEngine] Evaluation timed out after ...` / `Evaluation failed with error ...` — the LLM call
  itself failed open (warning level, from `evaluate_rules`).
- `[RulesEngine] Unexpected error resolving rule lock ...` — eligibility resolution (etcd/discovery)
  failed open, distinct from an LLM-call failure (warning level, from `search_agents`'s integration
  layer).

---

## Performance & Operational Notes

- The compiled rule catalog embedded in the LLM prompt is **not** token-bounded today. A deployment
  with many eligible agents each carrying several rules will produce a larger prompt, which can push
  real-world latency closer to (or past) `RULES_EVALUATION_TIMEOUT` under normal conditions — this
  shows up as routine fail-open-via-timeout rather than an outage. Keep the number of rules per agent
  small and specific (see [Writing Good Rules](#writing-good-rules)); if this becomes a bottleneck,
  monitor the timeout warning log volume as a leading indicator.
- Rule evaluation adds one extra bulk agent-discovery pass (to resolve which agents are currently
  configured/healthy) on top of what `search_agents()` already fetches, but **only** when at least
  one rule exists anywhere in the deployment — a zero-rules deployment (the default, out of the box)
  pays no extra cost per query.
- A rule lock returns **only the locked agent** when the caller's `limit` is `<= 0` or `1` (this
  includes the Gateway MCP tool's internal `limit=0` convention, which normally means "give me the
  full ranked catalog"). This is intentional — the point of a deterministic lock is one authoritative
  answer, not a muddied top-N — but it means a rule firing can reduce the number of results a caller
  gets back compared to an unlocked query. Pass an explicit `limit > 1` if you need the locked agent
  plus semantically-ranked alternates filling the remaining slots.
