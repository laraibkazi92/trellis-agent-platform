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
- The agent has an empty `rules:` list (nothing to evaluate).

Access-group / OIDC filtering is explicitly **out of scope** for this gating — it is not consulted
here.

> **Health and configuration-readiness are deliberately *not* part of this list.** An offline or
> unconfigured agent's rules are still compiled into the prompt and can still be matched — see
> [Availability: Handled After the Match, Not Before](#availability-handled-after-the-match-not-before)
> below. Only administrative disablement produces a full, silent exclusion here; offline/unconfigured
> is a separate, post-match concern.

If **no** eligible agent has rules and **no** global rules exist, the rules engine is skipped
entirely (`has_active_rules()` returns `False`) — the query goes straight to vector semantic search
with zero added latency, exactly as it did before this feature existed.

---

## Availability: Handled After the Match, Not Before

A confident rule match is only honored as a lock if the matched agent is also currently **available**
— this check happens in `core/agent_search.py:_resolve_rule_lock()`, strictly *after* the LLM decider
returns a confident match, using the same unified evaluators the rest of the platform uses (agent
health cooldown evaluation, configuration-readiness resolution):

- **Available** (Online, or a circuit-breaker-recovered "Half-Open" agent past its cooldown window)
  → the lock is honored normally: `search_agents()` returns **exactly one** result, the locked agent —
  this holds regardless of the caller's `limit`, including `limit <= 0`. A rules-engine lock is meant
  to be deterministic and authoritative, never diluted or truncated by the caller.
- **Offline**, or **unconfigured** (missing a required secret or variable) → the lock is *not*
  honored. `search_agents()` instead falls through to the normal ranked semantic fallback (governed by
  `limit` as usual) and prepends an "unavailable match" note:

  > The routing policy identified '\<agent>' as the best match for this query, but it is currently
  > offline / not configured. Showing next-best alternatives below.

  This note is **additional** to `limit`, not subtracted from it — a caller requesting `limit=5` still
  gets 5 ranked alternatives, plus the note, when this happens. The note item also carries
  `unavailable_match: True` (present on no other result) — both callers of `search_agents()` check this
  before re-decorating results by agent name (`core/gateway.py`'s MCP tool, `core/agent_factory.py`'s
  Supervisor tool), so its wording is never overwritten or double-annotated. It's still fully readable
  on its own if a consumer only looks at `description` and ignores the flag.

  > **Note:** the matched-but-unavailable agent is *not* filtered out of the ranked semantic-fallback
  > pool below the note — it can legitimately appear a second time among the alternatives, with its own
  > ordinary (undecorated) description, if it ranks well on its own. This is intentional, not a bug: the
  > note explains why the *rules-engine lock* didn't fire; the fallback ranking is a wholly separate
  > mechanism free to still surface the same agent as one candidate among several.

An administratively **disabled** agent never reaches this check at all — it's excluded from
eligibility outright (see [Readiness Gating](#readiness-gating) above), so no note is ever produced
for it; it's simply absent from consideration, same as before.

This design means a rules-engine lock, once returned by `search_agents()`, can never collapse to zero
results downstream — there's no second gate left that can disagree with it and drop it. A genuinely
separate, unavoidable race remains: the agent recommended at search time could still change state
(get disabled, lose a secret) in the window between search and actual invocation — that's handled by
`use_agent`'s fresh, single-agent, point-of-use configuration check immediately before dispatch, which
is the correct layer for that guarantee, not `search_agents()` itself.

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
4. **Administrative disablement**: disable `troubleshooting-agent` and repeat query 1. Its rules must
   not be evaluated at all — the query should fall through to remaining eligible agents, with no
   "unavailable match" note (disablement is a silent exclusion, not a post-match note).
5. **Offline/unconfigured match**: take `troubleshooting-agent` offline (or revoke a required secret)
   *without* disabling it, and repeat query 1. Its rules are still evaluated and still match — but the
   response should now lead with an "unavailable match" note naming it, followed by the normal ranked
   semantic-fallback alternatives (not a hard exclusion).

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
- A rule lock **always** returns exactly one result — the locked agent — regardless of the caller's
  `limit`, including `limit <= 0`. This is intentional: the point of a deterministic lock is one
  authoritative answer, never a muddied top-N, and the caller has no way to override it (there is no
  "bypass the rules engine" flag by design — see [Availability: Handled After the Match, Not
  Before](#availability-handled-after-the-match-not-before)). The Gateway MCP tool now passes its
  caller's real `limit` straight through to `search_agents()` rather than the old `limit=0`-then-
  truncate convention.
