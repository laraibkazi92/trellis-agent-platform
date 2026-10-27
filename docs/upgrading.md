# Upgrading Trellis

How an operator upgrades the Trellis **engine** (this repo) to a new release, and what
per-version hazards to check first.

This guide assumes the recommended split layout: the engine is cloned and pinned to a
release tag, and your agents/tools/workflows/mcps live in a separate content checkout
pointed at by `TRELLIS_WORKSPACE_DIR` (see `.env.example` → *Deployment Layout*). If you
run with the default `./workspace` inside this clone, the same steps apply, but be aware
that your content is then inside the tree you check out tags into.

The current release, `v0.7.1`, is breaking. Read [its section](#v071-2026-10-26) before
you upgrade.

---

## v0.7.1 (2026-10-26)

Changes since `v0.7.0`: this release **removes** machinery rather than adding it. The
in-process sandbox backends (`bwrap`, Landlock, the AppArmor profile), the network
profiles and the opt-in egress proxy are gone, so a `runner` container is the only place
a tool, an MCP session or a script workflow executes. Caller identity comes only from the
verified agent token. The three-switch tool-authorization stack is replaced by one
evaluator whose group rules live in `workspace/policies/tool_access.yaml`. Secrets reach a
container through its stdin instead of its configuration. A `background_script` workflow
runs as one container per run.

There are no compatibility shims beyond accepting an old manifest value with a warning:
each removal below names what replaces it. The resulting posture is described in
[deploy.md](deploy.md#execution-isolation), [tools.md](tools.md#container-execution-contract),
[workflows.md](workflows.md#how-a-script-workflow-runs) and [proxy.md](proxy.md).

**Runtime prerequisite.** `runsc` is still the isolation boundary. The feature set in this
release is validated against a `runsc` that reports **runtime-spec 1.2.1** in
`runsc --version`; run a current gVisor release and confirm that line, as described in
[deploy.md → Prerequisite: gVisor](deploy.md#prerequisite-gvisor-runsc). `runc` remains a
dev-machine and per-tool escape hatch.

#### Upgrade order

1. **Read this whole section first.** Two changes can bite silently: the `network:`
   default flip and the tool-access widening (an agent's allowlist, not the old policy
   document, is now what grants a call).
2. **Copy the rules you want to keep** out of `/registry/tool_policies` into
   `workspace/policies/tool_access.yaml` (format in the tool-access section below).
   Nothing migrates from the old document, and a malformed new file stops the whole
   stack.
3. **Rebuild or pull the images**, including `RUNNER_IMAGE` and every edge's
   `TRELLIS_IMAGE`: tool containers start through a shim that only v0.7.1 images carry.
4. **Keep `AGENT_TOKEN_SECRET` on every component that verifies a token**, including each
   edge **runner**. Tokens are now enforced by default.
5. **Deploy**: `docker compose pull && docker compose up -d`, or
   `docker compose up -d --build` when you build from source.
6. **Approve each edge key** in Admin → Edges. Every existing edge becomes pending until
   you do, and sealing is blocked until then.
7. **Audit each agent's `allowed_tools`/`allowed_mcps`**, then set `TOOL_ACCESS_MODE` if
   you do not want `enforce`.
8. **Exercise the three paths once**: a bound tool call, a script workflow, and one edge
   call.

#### Sandbox backends removed: a runner container is the only execution path

`SANDBOX_BACKEND` is gone, and with it every value it accepted: `auto`, `bwrap`,
`landlock` and `container`. The Landlock helper and its source (`sandbox/trellis-sandbox.c`),
`core/sandbox_preflight.py`, the in-process path in `core/sandbox.py`, `deploy/apparmor/`
and the bwrap/AppArmor CI legs were deleted. The hub no longer relaxes its own LSM
profile, because no tool process runs inside it.

Tools have executed in runner containers since v0.6, so the change is mostly deletions:

- The hub's `/healthz` is now a liveness probe (`{ok, backend}`). Runner readiness is the
  runner's own `GET /v1/healthz`; nothing reports it through the hub any more.
- Tool result dicts still carry the legacy `sandbox` key when the runner refuses a call.

**What to do instead**

- Nothing to configure or install: tool and MCP execution is the `runner` service, and
  there is no backend to select or pin.
- Delete these keys from `.env` if you carry them: `SANDBOX_BACKEND`, `SANDBOX_SECCOMP`,
  `SANDBOX_NET_DEFAULT`, `SANDBOX_UID`, `SANDBOX_GID`, `SANDBOX_TMP_ROOT`,
  `SANDBOX_RLIMIT_AS_MB`, `SANDBOX_RLIMIT_CPU_S`, `SANDBOX_RLIMIT_NPROC` and
  `SANDBOX_RLIMIT_FSIZE_MB`. Nothing reads them.
- Remove any `systempaths=unconfined`, `seccomp=unconfined` or `apparmor=unconfined` line
  from your own compose overrides. The hub keeps `cap_drop: [ALL]` and
  `no-new-privileges` and needs no exception. Unload a host-installed `trellis-hub`
  AppArmor profile if you added one.
- **Dev machines without gVisor** run the same runner with
  `CONTAINER_DEFAULT_RUNTIME=runc` (the default stays `runsc`). A per-tool
  `container_runtime: runc` still works. See
  [deploy.md → Dev machine](deploy.md#dev-machine-docker-desktop).

#### Network: `network:` is `egress` or `none`, and the default changes

The two tool networks (`trellis-tools-internal`, `trellis-tools-internet`), the
`DOCKER-USER` rules, the generated `resolv.conf` mounts and the CONNECT allowlist proxy
are gone, with the files that built them: `core/execution/netprofiles.py`,
`scripts/setup-network-profiles.sh`, `scripts/egress_proxy.py`,
`scripts/generate_egress_acl.py`, `docker-compose.egress.yml`,
`docker-compose.egress-ci.yml`, `docker-compose.ci-bwrap.yml` and
`docker-compose.ci-apparmor.yml`. The runner's network-profile check went with them; its
startup gates are now the runtime, the image, the tool identity and the manifest
runtimes.

A manifest's `network:` accepts exactly two values:

| Value | Where the container runs |
| --- | --- |
| `egress` (default) | Docker's **default bridge**, with whatever route and resolvers the host has |
| `none` | No network at all: no route, no loopback, no resolver |

The v0.6 profile names `allow`, `internet` and `internal` still load as `egress` and log
**one deprecation warning per distinct value per process** (the hub, the runner and
`db-sync` each log their own). `deny`/`off` load as `none`. An unrecognized value falls
back to `none` with a warning, so a typo can never hand a tool the network; `db-sync`
refuses an unknown `network:` in a workflow `config.yaml` outright.

**The default flipped.** A tool, an MCP session or a workflow that declares no `network:`
used to get no network and now gets `egress`. The interactive `execute` path is
unaffected: it is always `none`.

**Accepted risk, stated plainly.** With no profiles and no host firewall rules, `egress`
means what it says: a tool container can reach anything the Docker host can reach,
including private networks, internal services on the host's routing table, and the cloud
metadata endpoint (`169.254.169.254`). There is no per-destination allowlist in this
release. `network: none` is the only containment option, so set it on every manifest that
does not call an external API.

**Why the default bridge.** Under `runsc`, Docker's embedded DNS (`127.0.0.11`) on a
user-defined network is unreachable: both container-name and external resolution time out
(UDP), while the same lookup on the default bridge resolves because Docker copies the
host's real upstream resolvers into the container's `resolv.conf`. Tool, MCP and workflow
containers therefore ride the **default bridge**, and no `trellis-tools` network is
created. Two consequences, both deliberate:

- Containers on the default bridge can reach **each other** by IP, so one tool container
  is not isolated from another at layer 3.
- Engine services are not on the default bridge: compose puts them on the project network,
  so a tool cannot resolve `host`, `hub`, `relay`, `etcd` or `redis` by service name.
  Published front-door ports stay reachable through the host's bridge gateway, which is
  the same exposure any container on that bridge has. The runner itself runs with no
  network at all, so its control socket is never reachable from a tool container.

**What to do instead**

- Rewrite every `network: allow` / `internet` / `internal` in `tool.yaml`, `mcp.yaml` and
  workflow `config.yaml` to `egress` (or `none`). A `grep -rn "network:" workspace/` is
  usually enough.
- Set `network: none` explicitly on any manifest that must stay offline, including MCP
  servers that only touch a local socket.
- Delete these keys from `.env`: `TRELLIS_INTERNAL_CIDRS`, `TRELLIS_ENGINE_SUBNETS`,
  `TOOLS_INTERNAL_DNS`, `TOOLS_INTERNET_DNS`, `TOOLS_NET_INTERNAL_SUBNET`,
  `TOOLS_NET_INTERNET_SUBNET` and any `EGRESS_*` value.
- Drop `COMPOSE_FILE=...docker-compose.egress.yml` (and the `-f` form) from your upgrade
  commands; the file no longer exists.
- Tear down leftovers once on each host: `docker network rm trellis-tools-internal
  trellis-tools-internet` (nothing creates them any more) and delete any `DOCKER-USER`
  rules you added for the profiles.
- An `egress:` list in `tool.yaml` is now inert: the proxy that read it is gone. The field
  is still accepted so old manifests parse, and nothing enforces it.

#### Caller identity comes only from the agent token; body fields are gone

The verified agent token is the single source of caller identity. `user` and `user_email`
were removed from every request body (the relay's `CallBody`, the hub's `ExecRequest`, the
runner exec payload, stdio session creation and the console transport). The relay derives
the edge frame's identity from the token's claims (`u` user id, `e` email); the hub, the
runner and the edge read the same claims instead of a body. A background run carries a
service identity: `svc_agent_<name>` with no email and no groups.

**What to do instead**

- Nothing, for the shipped components: they all ship in one image and changed together. A
  custom caller that posts to the relay's `/v1/sites/{site}/call` must send `agent_token`
  and stop sending `user`/`user_email`; the relay logs one warning if it still sees them
  and ignores them, because a body can never assert an identity.
- A token minted without an email claim has no `TRELLIS_USER_EMAIL` at the edge, and a
  per-user-credential call from it now fails with **`identity_incomplete`** (a new code,
  deliberately not `credential_rejected`) instead of guessing an address from the user id.
  Tools can still branch on whether the variable is present at all: it is absent, not
  empty.
- Per-user sealed edge credentials need a **mintable** token. A deployment with no
  `AGENT_TOKEN_SECRET` mints nothing, so the call carries no claims at all: there is no
  verified identity to seal a set to, central looks none up, and the edge's
  `credential_mode` refuses the call rather than opening a set it cannot attribute.
  Configure the signing key, or use the shared edge credential file instead of sealing.

#### The edge proxy no longer verifies agent tokens

`trellis-proxy` verifies nothing. The relay authenticated the caller, verified the token
and built the frame identity from its claims; the edge trusts that identity over the
authenticated tunnel, the same trust it already placed in the relay's authorization
decision. **`AGENT_TOKEN_SECRET` leaves the edge proxy entirely.** The edge **runner**
keeps it: it verifies the forwarded token's signature and expiry and derives the agent and
the output directory from the claims. It makes no authorization decision of its own,
because the relay already made it for the call it forwarded. `RUNNER_AUTHORIZATION` and
the runner's own manifest allowlist check are gone.

Catalog publishing is per entry on both sides, so one bad manifest no longer costs the
tunnel:

- The edge validates every export before `hello`: a declared key that does not match
  `^[A-Za-z_][A-Za-z0-9_]*$`, an unpublished tool name or an unsupported transport skips
  **that export** with a warning, and the rest stay online.
- The relay's `hello` validation drops a single unusable tool, MCP or credential target
  and logs `edge hello site=...: not publishing '<name>': <reason>` instead of closing the
  tunnel. Only frame-level violations (wrong `proto`, unknown caps, a key whose
  fingerprint does not match, an oversized frame) still refuse the handshake.
- A credential-file line whose key is not a valid environment identifier is now logged
  with its line number and path instead of being silently skipped.

**What to do instead**

- Keep `AGENT_TOKEN_SECRET` in the edge's `.env`: the sample
  `deploy/proxy/docker-compose.yml` sets it on the **runner** service with `:?`, so compose
  refuses to start without it, and it is not set on `trellis-proxy` at all. It must be the
  same value central signs with, or every forwarded token fails verification.
- Create the edge and the central install from the same release. Relay frames and edge
  trust changed together; an edge on the new build verifies nothing, an edge on the old
  build still expects its proxy to verify.
- Rename a declared key that contains `-` or starts with a digit (for example
  `my-api-key` becomes `MY_API_KEY`) in `tool.yaml`/`mcp.yaml` and in the matching dotenv
  file. Until then that export is simply absent from central's catalog, with an edge log
  line explaining why.

#### Edge credentials: one shared file, sealed sets, and an admin-approved key

There are exactly two credential sources, and neither is a plaintext per-user file: the
shared `edge-secrets/<tool-or-mcp>.env` on the edge, and a browser-sealed set stored
centrally as ciphertext. The process-environment fallback for a declared **secret** is
removed: a key that lives only in the edge container's `.env` now resolves to unset.
Declared **variables** (endpoints, non-secret configuration) keep their `shared file`,
then process environment order. `env_passthrough: true` still hands a tool the whole
sanitized environment, which is its documented cost and not a credential path.

The last traces of the v0.5 plaintext store are gone too: `edge-user-secrets/`,
`proxy.yaml`'s `user_secrets_dir`, `TRELLIS_EDGE_USER_SECRETS_DIR`, the `user-secrets`
CLI and even the startup warning about a leftover directory. A directory or a config key
from that era is simply ignored now, so delete both.

Sealing is gated on an admin approving the key fingerprint. A newly published key (a
site's first hello, or the new half of `edge-keygen --rotate`) stays **pending** in
`/registry/edges/<site>/config` with `edge_key_approved: false`, and the seal endpoint
refuses to serve its public key (`409 key_pending_approval`) while Configuration → Edge
credentials shows the waiting fingerprint and keeps the form disabled. Only sealing is
gated: hello, catalog publishing, tool calls and sets already stored keep working.

**What to do instead**

- Move any credential that today lives only in the edge container's environment into
  `edge-secrets/<tool-or-mcp>.env` (mode `0600`) or seal it per user in the central UI.
- Delete a leftover `edge-user-secrets/` directory, its compose mount and its
  `proxy.yaml` key.
- After upgrading, and after every key rotation, open **Admin → Edges**, check the
  fingerprint and click **Approve key**. Every existing edge is pending until you do;
  during a rotation overlap the previously approved fingerprint stays approved, so blobs
  sealed to the old key keep opening, and `--drop-old-key` still ends the overlap.

#### Tool access rules: one evaluator, one mode, rules in the workspace

The three-switch etcd policy stack is gone. One evaluator (`core/tool_access.py`) decides
every call at every enforcement point: the hub (local and edge tools), the edge relay
(edge tool calls and MCP sessions), the host before it asks the runner for an `execute` or
MCP session call, and the bound-tool wrappers an agent gets from its own allowlist.

Two halves decide one call:

1. **The agent's allowlist**, resolved from its record (`allowed_tools`, `allowed_mcps`,
   `<site>__*` wildcards, console names). This half is enforced in every mode. A caller
   with **no agent record** is decided by the target's own `public`/`public_tools` flag.
2. **Group rules** from `workspace/policies/tool_access.yaml`. A target matched by at
   least one rule is usable only by a caller whose token groups intersect one of those
   rules; a target no rule matches is governed by the allowlist alone. Rules are
   allow-lists of groups with no priorities, no deny-overrides and no "everyone" group.

Removed with the old stack: the three per-surface switches (`tool_authz_mode`,
`bound_tools_mode`, `hub_call_mode`), the policy editor, **Bootstrap** and **Clear log**,
the principal-groups editor, `/registry/tool_policies`, `/registry/tool_authz_denies`, the
`principal_groups` mapping, the hub's stored-group lookup with its 30 s cache, and the
public-tool special case that used to live in `tool_search`. Admin → Tool Authorization
(`/admin/tool-authz`) is now **read-only**: it shows the loaded rules with their groups and
policy version, the current `TOOL_ACCESS_MODE`, every agent's effective allowlist and the
bounded shadow-denial ring (agent, target, reason, rule, groups, surface, timestamp).

One switch replaces the three: **`TOOL_ACCESS_MODE=off|shadow|enforce`**, default
`enforce`, and an unrecognized value behaves as `enforce` (a typo must never widen
access).

| Mode | What it does |
| --- | --- |
| `enforce` | Decisions are final. |
| `shadow` | A group-rule denial is logged and pushed onto the ring, then allowed. |
| `off` | The group-rule half is skipped. The allowlist half still applies. |

Neither relaxed mode touches the allowlist half, so a shadow window can never execute a
call outside the agent's manifest. Policy and registry reads **fail closed**: an
unreadable document, a failed registry read or an expired snapshot denies every call the
group rules could have decided, and the watch is installed in every enforcing process at
startup, so an edit lands everywhere within a second or two without a restart.

Four behaviours to plan around:

**(a) `default_action: deny` is gone, which widens access.** The new file has no
`default_action` key (it is a validation error if present): a target no rule matches is
governed by the agent's own allowlist. A call the old document denied for lack of a
matching rule can therefore be **allowed** now. **Audit every agent's
`allowed_tools`/`allowed_mcps` during the upgrade**, because the allowlist, not the policy
file, is what grants. A rule can only narrow a call, never widen one.

**(b) Service and workflow identities carry no groups.** A `background_agent` or
`background_script` run mints `svc_agent_<name>` with no group claim, so any rule matching
its tools denies that run (the caller holds no group, and a rule admits only holders). The
same applies to a delegated sub-agent minted from a service identity. There is no
group-less "everyone" rule: an empty `groups` list is a validation error.

**(c) A malformed policy file stops the whole stack.** The sync is strict on purpose: an
unparseable file, an unknown key, an empty `groups`, a duplicate rule or a duplicate name
makes `scripts/sync_to_db.py` print the errors and exit **2** without writing anything.
Because host, hub, gateway, the UI and the worker wait on `db-sync` with
`condition: service_completed_successfully`, a non-zero exit keeps the stack from coming
up. Fix the file and run `docker compose up -d` (or `trellis sync`); the registry keeps the
last valid policy, so a running stack keeps its previous rules. Deleting the file is safe
but silent: the sync warns and the registry keeps the old rules.

**(d) Only `execute` is covered among the console tools.** `read_file`, `write_file`,
`edit_file`, `ls`, `glob` and `grep` never pass through the evaluator. A rule naming one
is accepted, warns at sync and on the admin page, and decides nothing; those tools stay
constrained by the agent's console allowlist. `describe_tool` and the discovery catalog
reads are ungated for the same reason: they return schemas and execute nothing.

**What to do instead**

- Put group rules in `workspace/policies/tool_access.yaml`: a `rules:` list of
  `{name, targets, groups}`, where `targets` are shell globs matched against the reference
  the enforcement point uses (`text_stats`, `mcp__coralogix__list_alerts`, `dc1__node_ssh`,
  `mcp__dc1__devops-cli__kubectl`, `coralogix`, `execute`). `name` is an optional unique
  label; `groups` needs at least one name. The file ships with `rules: []` and commented
  examples; the format is documented in [tools.md → Tool access rules](tools.md#tool-access-rules).
- Set `TOOL_ACCESS_MODE` in the deployment environment. Start with `shadow` if you are
  adding rules to a live install, and check the ring on Admin → Tool Authorization before
  switching to `enforce`.
- Copy any hand-tuned rules out of `/registry/tool_policies` before you delete it; nothing
  migrates. The new format is one rule per target pattern with a group list, not
  principal/scope rules.
- Group membership reaches the decision only through the agent token's `g` claim (minted
  per run from the user record). A user whose groups exist only in the retired
  `principal_groups` mapping now has no groups for tool access; put them in the identity
  provider, or accept that a rule-guarded tool is closed to them.
- Re-bootstrap nothing: there is no bootstrap step any more, and a rule that matches a
  workflow's tool denies that workflow unless you relax the mode or drop the rule.

#### No principal exemptions: the supervisor and the gateway are ordinary agents

`principal="system"` and the `SYSTEM_PRINCIPALS` set are gone, together with every
exemption that honoured them: the hub's `gateway` bypass, the relay's supervisor and
gateway bypass, and the runner's. The supervisor mints an ordinary token and is checked
against **its own** manifest allowlist (the shipped `supervisor` asset binds `text_stats`
for exactly that reason); the gateway mints for the external caller's user identity, and a
caller with no agent record is authorized by the tool's own `public` flag.

Two consequences are intended:

- A supervisor or gateway call outside its manifest is denied, including a tool that used
  to reach through the framework's own identity.
- A supervisor or gateway **console or MCP session** is refused by design: the runner
  authorizes those two kinds from an on-disk agent manifest, and neither identity has one.
  No working path is lost, but do not route `execute` or an MCP session through the
  gateway.

Delegation now mints a child token at the `agent_factory` seam (both the supervisor's
sub-agent toolset and the A2A capability), carrying the parent run id in its `p` claim and
restoring the parent token when the child run ends. A sub-agent is therefore checked
against **its** allowlist, not its parent's. In `ENFORCE_AGENT_TOKENS=log` or `off` a mint
failure falls back to the parent token with a warning; in `enforce` it fails the call.

**Bare `allowed_tools` names no longer grant MCP tools.** A bare name matches only that
exact registered tool. An MCP tool needs `allowed_mcps` (whole server) or its full
`mcp__<server>__<tool>` reference, and an edge MCP tool needs the 4-part
`mcp__<site>__<mcp>__<tool>` form. The build-time MCP registration and
`permits_mcp_session` apply the same rule, so the runtime and the compiled toolset agree.

**What to do instead**

- Add `allowed_mcps` (or the full `mcp__...` names) to any agent that relied on a
  same-named MCP tool through `allowed_tools`.
- Give the supervisor and gateway agents the tools they actually need in their own
  manifests. A missing binding now fails that call instead of falling back to a framework
  identity.
- The `principal` claim (`k`) and the `principal=` argument on `agent_token.mint` /
  `mint_for_run` are **removed**. Existing tokens still verify and the extra claim is
  ignored; delete the argument from your own scripts.
- A token minted for a service identity is an ordinary token: it gets no elevated identity
  and no extra grant beyond the target's own public exposure.

#### Secrets reach a container through stdin, never through its configuration

Every tool, MCP-session, console and workflow container is started through a small
entrypoint shim, `trellis-exec`, installed in the engine image at
`/usr/local/bin/trellis-exec` (images derived from the engine image inherit it). Resolved
secrets therefore never reach the container's environment, where `docker inspect`, a
support dump or a debugging session would show them. The runner writes one JSON line to the
container's stdin first, `{"env": {"NAME": "value", ...}}`; the shim merges those values
into the process environment (the preamble wins) and `exec`s the real command in place, so
the process still reads them with `os.getenv()`.

- Everything after the preamble newline is the call's own stdin, byte for byte: the
  stdin/stdout tool protocol and MCP stdio framing are unchanged.
- A missing, oversized or malformed preamble makes the shim exit **78** without running
  anything, and it never logs a key or a value. The caps are **64 KiB for the whole line**
  and **16 KiB for one value**, sized against what `execve` accepts.
- `docker inspect` on a running container now shows only a fixed non-secret allowlist of
  18 names (`HOME`, `PATH`, `TMPDIR`, `TMP`, `TEMP`, `LANG`, `LANGUAGE`, `LC_ALL`,
  `LC_CTYPE`, `TZ`, `TERM`, `PYTHONUNBUFFERED`, `SSL_CERT_FILE`, `SSL_CERT_DIR`,
  `REQUESTS_CA_BUNDLE`, `TRELLIS_USER_ID`, `TRELLIS_USER_EMAIL`, `TRELLIS_RUN_ID`) plus
  whatever your own compose `environment:` adds. A name that looks like a credential is
  refused by the allowlist even if someone adds it there by mistake.
- A declared secret or variable whose name cannot be an environment variable (`my-secret`,
  or one starting with a digit) is now a **sync error**: `db-sync` prints the name and
  exits **2** instead of publishing a manifest that would lose the credential at the last
  mile. The runner rejects the same name with a `400`, and the shim would otherwise have
  refused the whole line and taken the tool's other credentials with it.
- One-shot containers are removed as soon as the result is collected, and session
  containers on close or eviction.

**What to do instead**

- Set `RUNNER_IMAGE` (and each edge's `TRELLIS_IMAGE`) to **v0.7.1 or newer**. An older
  image does not degrade gracefully: no tool container can start (the entrypoint is
  missing, so containers exit `126`/`127` or the daemon refuses the start), and the
  runner's startup canary refuses to serve calls. The canary names the image when the shim
  is what is missing. The runner never pulls an image itself, so it must already be
  present locally.
- Keep `/usr/local/bin/trellis-exec` as the entrypoint of any tool image you build. A
  manifest `image:` that points somewhere else must provide the shim or an equivalent that
  reads the same one-line preamble.
- Do not debug by reading a container's environment; that is the point of the split. A
  value you need to see belongs in the tool's own output or the run log.
- Rename invalid declared keys in `tool.yaml`/`mcp.yaml`/`config.yaml` and in the matching
  dotenv file: `my-secret` becomes `MY_SECRET`.

#### Runner and token enforcement defaults

`RUNNER_AUTHORIZATION` is gone, and so is the runner's own manifest allowlist check. The
runner still verifies `RUNNER_TOKEN` on the socket, verifies a forwarded token's signature
and expiry, derives the agent and the output directory from its claims, and keeps the
`kind: "discovery"` read (socket-token gated, engine internal). It makes no authorization
decision: every decision belongs to `core/tool_access.py` at the enforcement point that
owns the caller.

**`ENFORCE_AGENT_TOKENS` now defaults to `enforce` in code**, not in compose. An unset or
unrecognized value enforces. `off` is a local-development posture that requires
`DEV_MODE=true`; without it the value is refused with an error and `enforce` applies. `log`
remains the one intentional rollout window: it records the would-be denial and lets the
call through. Tokens also carry the caller's groups (`g`, read once at mint from the user
record) and a parent run id (`p`) used by delegation.

**What to do instead**

- Set `AGENT_TOKEN_SECRET` (32+ bytes, `openssl rand -hex 32`) on every service that
  verifies a token, on central and on each edge runner. With the default `enforce`, a
  `DEV_MODE=true` stack that has no secret now **exits at startup**.
- For a throwaway local stack you may set `ENFORCE_AGENT_TOKENS=off` together with
  `DEV_MODE=true`. Do not use it on anything shared.
- If you carry `RUNNER_AUTHORIZATION` in `.env` or an edge config, delete it: nothing
  reads it.

#### `background_script` workflows run in one container per run

A script workflow used to be an ordinary subprocess of the `taskiq-worker`: it inherited
the worker's environment, saw the whole workspace read-write and could reach the engine's
own services by name. It is now **one runner container per run**, created from the same
image and runtime as a tool (`runsc` by default). The pipeline's own contract does not
change: it is still a plain process reading its event payload on stdin and writing to
stdout. What surrounds it does:

| Mount | Container path | Mode |
| --- | --- | --- |
| the workflow's own directory | `/app/workspace/workflows/<name>` | read-only, and the **working directory** |
| shared code | `/app/workspace/shared` | read-only (when it exists) |
| the tool suites its `allowed_tools` names | `/app/workspace/tools/<suite>` | read-only |
| the workflow's output dir | `/app/workspace/output/<name>` | read-write |
| the workflow's report dir | `/app/workspace/reports/<name>` | read-write |
| scratch space | `/tmp` | tmpfs (`limits.tmpfs_mb`) |

Everything else is absent: no other workflow, no suite the workflow did not declare, no
`agents/`, `mcps/`, `.env` or registry state. That *is* the enforcement: a workflow
container carries no agent token and makes no hub round trip, so a tool it did not declare
is simply not on the filesystem. Enforcement is per **suite**, not per tool: a suite
holding none of the workflow's `allowed_tools` is not mounted at all, while a tool that
shares a suite with an allowed one is present and runnable. `allowed_tools` decides which
directories appear, not which executables inside them may be started. A workflow that
declares an edge tool or an MCP tool is legal (that list is also the run's allowlist), it
just has no files to mount.

Four behaviours to plan around:

1. **Only declared secrets and variables exist.** The container does not inherit the
   worker's environment any more. `SESSION_SECRET`, `ENCRYPTION_KEY`, `RUNNER_TOKEN`,
   provider keys and every operator-defined variable in the worker's own environment are
   gone; the pipeline sees exactly the keys its `secrets`/`variables` blocks declare (plus
   whatever the tools it declares require), delivered through the `trellis-exec` preamble
   so they never appear in `docker inspect`. A pipeline that quietly relied on an
   undeclared variable now reads nothing.
2. **The worker no longer writes the workspace, except `reports/`.** `taskiq-worker` mounts
   the workspace **read-only**; only `workspace/reports/` stays read-write, for a
   `background_agent`'s in-process file tools. A pipeline that wrote anywhere else in the
   workspace now fails, so write under `output/<name>/` or `reports/<name>/`.
3. **Cancelling a run mid-flight does not stop the container.** The runner has no cancel
   API, so the container runs to its deadline; the run is then recorded as cancelled
   (`run_cancelled`, `container_stopped: false`) without the worker claiming execution
   stopped. Cancel before the run starts, or shorten `WORKFLOW_RUN_TIMEOUT`
   (Admin → Limits & Tuning, default `3600` s) if a workflow must be bounded.
4. **One container per run costs latency and a slot.** Each scripted run pays container
   create/start/teardown (roughly a second, more on a cold `runsc` image), and a run's
   steps share that container, so they share its files, its `/tmp` and the one secret set:
   nothing is isolated between the steps of one pipeline. The run also holds one of the
   runner's **global** container slots (`RUNNER_MAX_CONTAINERS`, default `32`) until it
   finishes, so a pipeline that sits until its deadline keeps that slot, and enough of them
   push ordinary tool calls into `429 capacity_exhausted`. Size the global cap for
   workflows and interactive calls together.

**What to do instead**

- Run each pipeline once by hand after upgrading (Workflows → Run) and check its output and
  `workspace/reports/<name>/`. A missing declared secret or a write outside
  `output/`/`reports/` is the failure mode this change introduces.
- Add every credential and endpoint the pipeline reads to its `config.yaml`
  (`secrets:`/`variables:`, or through the tools it declares) and set the values in
  Workflows → Secrets. Undeclared values no longer leak in from the worker.
- Remove any pipeline dependency on engine hostnames (`HOST_URL`, `HUB_URL`,
  `http://host:8000`, `http://hub:8001`): a workflow container gets ordinary Docker egress,
  not the compose project network. Call the API with an explicit URL (`PUBLIC_HOST_URL`)
  and a declared token, or do the work through a declared tool.
- Read `TRELLIS_AGENT_NAME` (the workflow name) inside a tool the pipeline shells out to,
  to find where it should write `reports/<name>/`. A workflow container has no agent token,
  so this variable is how a pipeline, and any tool it launches with its own environment,
  learns which workflow it is running for.
- `db-sync` validates a `background_script`'s `runtime`, `entrypoint`, `network`, `limits`,
  `allowed_tools` and declared env names before publishing it: an unknown `limits` knob, a
  runtime outside the four supported values, an `entrypoint` that is not a plain relative
  path or is not present, an unknown `network`, or an invalid env name stops the sync with
  exit 2 and writes nothing. Those used to sync and then fail one scheduled run at a time.
- `runtime:` accepts `python` (the default), `node`, `bash` and `exec`. `exec` runs the
  entrypoint as given (a shebang script or a binary). A config already in the registry that
  names something else still runs its entrypoint directly with a warning; pin one of the
  four.
- A workflow `limits:` block overrides only the knobs it names; the rest stay at the
  workflow defaults (4 GiB memory, 2 CPUs, 1024 pids, 1 GiB tmpfs), never a tool's 512 MiB.

#### Changes to declare

- **Compose services:** none added or removed. `hub` loses the LSM exceptions it carried
  for the in-process sandbox, and `taskiq-worker` mounts the workspace read-only with
  `workspace/reports/` read-write.
- **`.env` keys:** added `TOOL_ACCESS_MODE` (default `enforce`). Removed and now ignored:
  `SANDBOX_*`, `TRELLIS_INTERNAL_CIDRS`, `TRELLIS_ENGINE_SUBNETS`, `TOOLS_INTERNAL_DNS`,
  `TOOLS_INTERNET_DNS`, `TOOLS_NET_INTERNAL_SUBNET`, `TOOLS_NET_INTERNET_SUBNET`,
  `EGRESS_*`, `RUNNER_AUTHORIZATION`. `AGENT_TOKEN_SECRET` is required on central and on
  each edge runner, and `RUNNER_IMAGE` must be v0.7.1 or newer.
- **Registry sync:** new `workspace/policies/tool_access.yaml` (published to
  `/registry/tool_access`); an invalid policy file or an invalid workflow config now
  aborts the sync with exit 2. `/registry/tool_policies`, `/registry/tool_authz_denies` and
  `/config/framework/{tool_authz_mode,bound_tools_mode,hub_call_mode,principal_groups}` are
  never read again.
- **Tool protocol / `workspace/` layout:** the stdin/stdout protocol is unchanged; add
  `workspace/policies/`. The visible filesystem inside a tool is unchanged. A tool container
  can no longer see the engine's services by name, and `network:` means `egress` or `none`.
- **Data migrations:** none. Existing users, API keys, run history and sealed credential
  sets are unaffected; each edge key needs one approval in the UI.
- **Image pins:** `TRELLIS_IMAGE` and `RUNNER_IMAGE` must both be v0.7.1 or newer, on
  central and on every edge.

---

## Versioning & the compatibility promise

Releases are tagged `vMAJOR.MINOR.PATCH`. `v0.2.0` is the first release.

| Surface | Status |
| --- | --- |
| `workspace/` layout — `agents/`, `tools/`, `workflows/`, `mcps/`, `shared/`, `policies/` | Public API |
| Tool protocol — JSON arguments on `stdin`, JSON results on `stdout` | Public API |
| Agent `config.yaml` / `skills.md`, `tool.yaml`, `mcp.yaml` manifests | Public API |
| `docker-compose.yml` services, `.env` keys, registry sync behavior | Stable, but changes are announced per release below |
| Internal modules under `core/`, module import paths, `scripts/` internals | Not stable |

During 0.x, **breaking changes may land in minor releases** (e.g. `0.2` → `0.3`). Every
breaking change is listed in the per-release notes below. Pin the engine to a release tag;
`main` is upstream development and may contain unreleased breaking changes.

Because the workspace layout and the tool protocol are the API-facing part of the engine,
your content repo is expected to keep working across engine upgrades. If a release requires
a change on your side, it is called out explicitly.

---

## Standard upgrade procedure

Run from the engine clone:

```bash
git fetch --tags
git describe --tags            # note the tag you are on now, for rollback
git checkout v0.4.1            # target release tag
docker compose pull            # fetch the multi-arch app image for that tag
docker compose up -d           # recreate services; nginx-gateway is built from ./gateway
```

Notes:

- `docker compose pull` fetches the app image published to GHCR
  (`ghcr.io/laraibkazi92/trellis-agent-platform:vX.Y.Z`). The `nginx-gateway` service has no
  remote image — it is built locally from `./gateway` on `up`.
- If you build from source instead of pulling (`TRELLIS_IMAGE` unset or overridden), use
  `docker compose up -d --build`; that ignores the image default and builds locally.
- The `db-sync` init container runs on every start and re-syncs your workspace into etcd.
  An engine upgrade therefore does **not** touch your content repo, and does not touch users,
  API keys, or run history in etcd. It does rewrite the registry entries derived from your
  workspace, so the registry always reflects the current state of your content checkout.
- `.env` is not managed by the upgrade. Keep your existing `.env`; diff it against the new
  `.env.example` for added/removed keys. New optional keys have working defaults.
- There is no app-side schema migration: framework runtime state lives in etcd, so the only
  migrations are the per-release ones listed below.

---

## Rollback

```bash
git checkout v0.2.1            # previous tag
docker compose pull
docker compose up -d
```

Rolling back the engine code and images is safe for your content and etcd data, with two
caveats:

1. **State migrations are one-way.** The etcd 3.5 → 3.6 storage migration cannot be undone by
   checking out an older tag (see below). Snapshot before upgrading, or you cannot go back.
2. **Volume state is not versioned.** Volumes (`etcd-data`, `health-data`, `hindsight-data`)
   persist across tag changes. A rollback does not restore an older schema or older embedding
   data; do not rely on rollback to fix a bad data migration.

Pin the tag you are rolling back *from* before you upgrade (`git describe --tags`), so the
rollback command is unambiguous.

---

## Per-release notes

These apply when moving **onto** the listed release. They also already apply to deployments
created before that release that are running the current images (the etcd minor and the
Hindsight image pin changed in `main` ahead of the tag).

### v0.2.0

| Area | Hazard |
| --- | --- |
| etcd | 3.5 → 3.6 storage migration is one-way. Snapshot first. |
| Container user | Changing `TRELLIS_UID`/`TRELLIS_GID` leaves existing volumes owned by the old uid. |
| Agent memory | Changing Hindsight embeddings model or dimensions after first use breaks recall. |
| Agent search | Changing `AGENT_EMBEDDING_MODEL` invalidates stored agent embeddings; re-embed. |
| Hindsight image | Server image tag must match `hindsight-client` in `requirements.txt`. |

#### etcd 3.5 → 3.6 storage migration (one-way)

The compose stack pins `gcr.io/etcd-development/etcd:v3.6.x`. Upgrading an existing 3.5 data
directory in place is supported, but **one-way**: once the data dir has been migrated to the
3.6 storage version, rolling back to a 3.5 image requires a snapshot/restore. Pulling the
older image and restarting is not enough.

Snapshot before you upgrade:

```bash
# take the snapshot, then copy it off the etcd-data volume
docker compose exec etcd etcdctl snapshot save /tmp/pre-upgrade.db
docker compose cp etcd:/tmp/pre-upgrade.db ./pre-upgrade-etcd.db
```

Keep that file outside the clone and off the `etcd-data` volume, since a snapshot that only
exists inside the volume is lost with the volume. Snapshot *before* the first start on the
new etcd image; a snapshot taken after migration no longer restores a 3.5-compatible state.

#### Changing `TRELLIS_UID` / `TRELLIS_GID`

The app containers run as `TRELLIS_UID:TRELLIS_GID` so files written into the bind-mounted
workspace are owned by you instead of root. Two consequences when you change these values:

- Files already in the bind-mounted workspace are still owned by the **old** uid/gid.
- The `/app/data` health volume inherits its ownership when it is **first created**. If it
  already exists root-owned, the new uid cannot write to it.

Remove **only** the health volume and recreate:

```bash
docker compose down
docker volume rm "$(basename "$PWD")_health-data"
docker compose up -d
```

Do **not** use `docker compose down -v` here. That also deletes the `etcd-data` volume,
which holds users, API keys, and run history.

Fix workspace file ownership on the content checkout (outside Docker) with `chown`/`chmod`
as you would for any other directory. The `hub` service runs as `${TRELLIS_UID:-1000}` like
the rest of the app containers; this does not affect the other services.

#### Hindsight embeddings: model, provider, or dimensions

Agent memory is backed by Hindsight. Its embedding provider, model, and output dimension are
set in `.env` (`HINDSIGHT_EMBEDDINGS_PROVIDER`, `HINDSIGHT_EMBEDDINGS_MODEL`,
`HINDSIGHT_EMBEDDINGS_DIMENSIONS`) and materialized into the `hindsight-data` volume on first
use.

Change any of these **before** the first use of the new setting. If you change them after
data exists, stored vectors have the old dimension and recall breaks on a mismatch. To
recover, wipe the volume and start clean:

```bash
docker compose down
docker volume rm "$(basename "$PWD")_hindsight-data"
docker compose up -d
```

This deletes stored memories. There is no in-place re-embedding path; re-embedding happens
by starting fresh.

For reference, `gemini-embedding-2` supports output dimensions 128–3072 (recommended 768 /
1536 / 3072) and auto-normalizes truncated dimensions; `gemini-embedding-001` is text-only.
The embeddings provider value for Gemini/Google is `google`, not `gemini`.

#### `AGENT_EMBEDDING_MODEL` and semantic agent discovery

Semantic agent discovery (`search_agents` / `auto_select`) indexes agents at sync time using
the embeddings model selected in **Admin → Limits & Tuning** (`agent_embedding_model`) and the
Google key configured in **Admin → LLM Providers**. Changing `AGENT_EMBEDDING_MODEL`
invalidates every previously stored agent embedding. Re-embed by rebuilding / re-running the
registry sync (a `docker compose up -d --build`, or `python scripts/trellis sync` from inside
a container) so `search_agents` works again. Until then, semantic search falls back to
keyword matching.

#### Hindsight server image vs. `hindsight-client`

The Hindsight server image tag and the `hindsight-client` pin in `requirements.txt` must
match. This is a single upstream monorepo that publishes the Python client and the server
image together under the same version number, and consecutive minor releases include real
API-surface changes. On each engine upgrade, confirm the two agree:

```bash
grep hindsight-client requirements.txt
grep 'ghcr.io/vectorize-io/hindsight' docker-compose.yml
```

The image is the `-slim` variant (no bundled local ML models, relies on the Gemini API for
LLM and embeddings). Because of that, the `local` reranker is unavailable and the default is
`rrf` (Reciprocal Rank Fusion passthrough).

### v0.2.1 — 2026-10-18

Changes since `v0.2.0`.

#### LLM provider expansion (pydantic-ai 2.57.0)

Existing agents and etcd data keep working; the only action is a rebuild so the new
dependencies are installed.

- **Dependencies:** `requirements.txt` now pins `pydantic-ai[huggingface]==2.57.0` and
  `google-genai==2.31.0` (was `pydantic-ai==2.31.0` / `google-genai==2.18.1`). Do not keep
  the old `google-genai` pin: it breaks Google model dispatch. Rebuild with
  `docker compose up -d --build`.
- **No etcd migration.** Provider credentials are still one flat dict at
  `/identities/system/system/llm_keys`. The existing `GEMINI_API_KEY`, `GOOGLE_API_KEY`,
  `OPENAI_API_KEY`, and `ANTHROPIC_API_KEY` entries keep their names and precedence, and
  the four legacy `provider` values still resolve.
- **New page.** Provider keys are no longer on the tool/MCP secrets page; they live on
  **Admin → LLM Providers** — one card per provider. The tool-secrets page keeps tool/MCP
  secrets and variables. The keys for the 11 new providers (DeepSeek, Fireworks AI, Together AI,
  Moonshot AI, Vercel AI Gateway, Z.AI, OpenRouter, Alibaba, Ollama, LiteLLM, Hugging Face)
  are set there.
- **`openai-compatible` key name:** `OPENAI_COMPATIBLE_API_KEY` is the preferred name;
  `OPENAI_API_KEY` is still accepted, so deployments that never set the new name keep
  working.
- **Ollama needs a base URL.** pydantic-ai 2.57 refuses to guess one, and Trellis always
  passes an explicit value; it defaults to `http://localhost:11434` and can be overridden
  per agent or globally on the new page (`OLLAMA_BASE_URL`).
- **`base_url` is now honoured for `google`/`openai`/`anthropic`.** The old resolver ignored
  a per-agent `base_url` for these three (it only mattered for `openai-compatible`). A stale
  endpoint left on an existing agent will now be used — remove it if it was not intentional.
  Providers that cannot take an endpoint (`deepseek`, `openrouter`, …) reject one with a clear
  error instead of silently dropping it.

#### Framework LLM defaults

An admin can now set one org-wide default provider + model in **Admin → LLM Providers →
Framework defaults**. Agents and background workflows that leave both `provider` and `model`
blank inherit it; the value lives only in etcd and is never written into an agent's YAML.

- **Behaviour change — call this out.** An agent or workflow with `model` blank used to build a
  model with an **empty id** and fail on the first request. It now resolves — either to the
  admin's framework default, or, when nothing is configured, to `google` / `gemini-2.5-flash`.
  A config that has never served a request may therefore start running (and billing). This only
  affects configurations that were already broken; a fully-specified agent is unchanged.
- **A provider with a blank model now resolves** to that provider's registry default (e.g.
  `deepseek` → `deepseek-chat`) instead of failing. `openai-compatible` still requires an
  explicit model — it has no registry default.
- **`litellm` endpoint default.** A `litellm` agent, workflow, or framework default with no
  `base_url` now resolves to `http://localhost:4000`. Previously no endpoint was passed at all,
  and the underlying OpenAI SDK silently fell back to `https://api.openai.com/v1` — sending the
  gateway credential to a host the operator never chose. Set `base_url` explicitly when the
  LiteLLM proxy runs elsewhere; `localhost` inside the host container is only reachable in the
  same network namespace.
- **Workflow schema widening.** `AgentUpdateModel.model` is now optional, so background agents
  can be saved with a blank model (inherit). This is a widening only: every existing stored
  workflow keeps its model and is unaffected.
- **New etcd keys, no migration.** The default lives at
  `/config/framework/default_llm_provider`, `/config/framework/default_llm_model`, and
  `/config/framework/default_llm_base_url`. All three are empty by default, and empty means
  today's behaviour apart from the case-E fallback above.
- **Rules decider pairing.** An admin provider override with a blank model now persists that
  provider's registry default instead of pairing the override with the environment
  `RULES_EVALUATION_MODEL` (which could egress to the wrong vendor). Deployments that set only
  `RULES_EVALUATION_MODEL` with no provider override are unchanged.
- **Endpoint environment residual.** Trellis always passes a configured `base_url` explicitly
  to the provider SDK, but for a provider that supports an endpoint and has **no** configured
  `base_url` — neither per-agent, nor the framework default, nor a global store — the SDK may
  still read its own endpoint environment variable (for example `OPENAI_BASE_URL`). Set the
  endpoint explicitly if you do not want that fallback.

### v0.3.0 — 2026-10-20

Changes since `v0.2.1`: tool sandboxing, per-tool network policy, and opt-in egress mode. The
`TRELLIS_IMAGE` default moves to `v0.3.0`; `docker compose pull && docker compose up -d`
recreates the hub with the new posture.

#### Tools now run inside a sandbox

The hub probes two backends at startup and picks **bwrap** where it works, otherwise
**Landlock**. `/healthz` reports the verdict (`backend`, `code`, `remediation`).

- **Filesystem:** `/` is read-only, `/app/workspace` read-write, `/tmp` a private tmpfs
  (nothing persists), `/var/tmp` and sensitive paths such as `/etc/shadow` denied. A tool that
  wrote outside the workspace now fails with `Permission denied` — move its data under
  `/app/workspace` or into the tool directory.
- **Identity:** the hub and its tools run as `TRELLIS_UID` with no capabilities
  (`cap_drop: [ALL]`). See the root-owned files section below.
- **Limits:** 8 MiB stdout / 256 KiB stderr per call, 4 GB address space, 600 s CPU, 64 MB
  file size, and `pids_limit: 1024` per container.
- **Docker options:** the hub requires `seccomp=unconfined`, `systempaths=unconfined`, and
  `apparmor=unconfined` (shipped in `docker-compose.yml`). Removing them breaks bwrap.
- **Ubuntu 24.04:** `apparmor_restrict_unprivileged_userns=1` refuses user namespaces to
  unconfined containers, so bwrap is unavailable and the hub falls back to Landlock
  automatically. To keep bwrap, install `deploy/apparmor/trellis-hub` (requires AppArmor 4.0
  userspace; validated in CI) or relax the sysctl.
- **Kernel support:** Landlock needs ABI 3+ (Linux 6.2+). With neither backend available,
  tool calls fail closed and `/healthz` reports why.

#### Root-owned files in the workspace from the old root-hub posture

The hub and its tools now run as `TRELLIS_UID` with no capabilities (`cap_drop: [ALL]`, no
`cap_add`). That applies to tool subprocesses too: under bwrap they are no longer uid 0
inside their namespaces. Deployments that previously ran the hub as root may therefore have
root-owned files and directories under `/app/workspace` that bwrap tools created as uid 0.

What you see: a tool that used to work now fails with `Permission denied` when writing to
one of those paths (the tool can read them, since world-readable, but not create or replace
entries). The failure is DAC, not the sandbox — the same write would fail for any
non-root user.

Remedy, outside Docker, on the host that holds the bind mount:

```bash
# whole workspace (simplest)
sudo chown -R "$TRELLIS_UID:$TRELLIS_GID" ./workspace
# or only the offending trees, e.g.
sudo chown -R "$TRELLIS_UID:$TRELLIS_GID" ./workspace/tools/foo/data
```

Also confirm `SANDBOX_UID`/`SANDBOX_GID` match the hub uid — they default to
`TRELLIS_UID`/`TRELLIS_GID`, and a non-root hub cannot drop to a different identity, so a
mismatch means Landlock tools run as an identity that does not own the workspace.
`SANDBOX_UID` no longer defaults to a separate "tool" identity; on the default deployment it
is the hub's own uid.

Rollback to the root-hub posture (removing the hub's `user:` line and restoring the old
capabilities) is only justified when a host cannot run bwrap as a non-root user at all — it
reintroduces the privilege-separation problem this migration removed. That rollback path
was deleted in `v0.7.1` along with the backend itself: see
[v0.7.1](#v071-2026-10-26).

#### Per-tool network policy

`tool.yaml` gains `network: allow|none` (default **allow**). `none` gives the tool no IP
network at all: bwrap uses a private network namespace; Landlock denies TCP connect/bind and
a seccomp rule refuses UDP/raw sockets. Loopback is blocked as well.

- Set `network: none` on every tool that does not call an external API — that is the cheapest
  exfiltration control available.
- `SANDBOX_NET_DEFAULT=none` flips the default for tools that do not set the field.
- `SANDBOX_SECCOMP=off` weakens `none` to TCP-only under Landlock (UDP/raw become reachable);
  the hub warns at startup. Keep seccomp on.

#### Opt-in egress mode

`docker-compose.egress.yml` moves the hub onto an internal-only network whose only route out
is a CONNECT proxy that connects to domains declared in `tool.yaml` `egress:`. It is off by
default. Enable it with `COMPOSE_FILE` in `.env`. The whole mechanism (the compose files,
`scripts/egress_proxy.py`, the ACL generator and the `egress:` list) was removed in
`v0.7.1`: see [v0.7.1](#v071-2026-10-26).

#### Probe lifecycle

`/healthz` re-probes and re-selects after a classified sandbox failure (at most once per
minute), so a host change is picked up without a restart. This is one-directional: a hub that
started with no working backend still needs one restart after the host is fixed.

#### Upgrade actions

1. `docker compose pull && docker compose up -d` — recreates the hub with the new user,
   capabilities, limits, and healthcheck.
2. Check `/healthz`: `ok: true` and the expected `backend`; if not, the payload carries a
   `code` and `remediation`.
3. Fix root-owned workspace files if the previous deployment ran the hub as root (section
   above).
4. Audit tools: move writes into `/app/workspace`, and add `network: none` where no external
   API is used.

---

### v0.4.0 — 2026-10-21

Changes since `v0.3.0`: edge nodes (`trellis-proxy`), so tools can run on a host that only
dials out. The `TRELLIS_IMAGE` default moves to `v0.4.0`. The central side (`edge-relay`
service plus the `/edge` route) ships in the same compose file, and **edges themselves are
opt-in** — an install that never enrolls one keeps behaving exactly as it did on `v0.3.0`.

#### What an edge is

A `trellis-proxy` node runs this same image on the host where the tools live and opens an
**outbound-only** tunnel to the central install. No inbound port and no VPN. The hub treats
the edge's tools as ordinary tools: they appear in the registry as `<site>__<tool>`, run
under the same sandbox policy *on the edge*, and their files stay on the edge host.

- New service: `edge-relay` (central side, internal port 8100) — nginx routes `/edge` to it.
- New admin page: **Admin → Edges** — site enrollment, live connections, revocation.
- Enrollment: create a site in the UI, copy its token to the edge host. Authoring and the
  protocol are in [proxy.md](proxy.md); the edge-side compose file is `deploy/proxy/`.
- Edge tools are written into etcd by the relay and marked `managed_by: edge-relay`. The
  registry sync (`scripts/sync_to_db.py`) **preserves** those entries — they never exist on
  central disk, so without that carve-out every `db-sync` would delete every remote tool.
  An undecodable edge config fails closed rather than being pruned.
- TLS for the tunnel (either terminating on the main nginx or in a dedicated `/edge`
  terminator): [proxy-tls.md](proxy-tls.md). Note the fail-loud caveat there — a wrong
  `EDGE_MTLS_CA` path stops nginx, taking the UI and API down with `/edge`, not just `/edge`.

#### New `.env` keys (all optional, defaults shown)

| Key | Default | Purpose |
| --- | --- | --- |
| `EDGE_RELAY_URL` | compose service name | hub → relay address, for a split-host install |
| `EDGE_TOOL_RECONCILE_SECONDS` | `10` | how often the hub re-reads relay-published tools (`0` disables) |
| `EDGE_AUDIT_LOG` | `/app/data/edge-audit.log` | relay audit trail (inside `health-data`, 10 MB × 5) |
| `EDGE_RATE_LIMIT_PER_MIN` / `_RPS` / `_BURST` | `120` / `30` / `20` | per-site call budget; a site record can override the per-minute value |
| `EDGE_MTLS_CA` | unset | CA bundle for edge client certs; requires `SSL_ENABLED=true` |
| `TRELLIS_VERSION` | the release tag on a pulled image; `dev` on a local build | reported in the edge hello frame and **Admin → Edges** |
| `EDGE_DEV_SITE` / `EDGE_DEV_TOKEN` | unset | **DEV ONLY**, ignored unless `DEV_MODE=true`; plaintext, no rotation, no audit |

#### Upgrade actions

1. `docker compose pull && docker compose up -d` — pulls `v0.4.0` and starts `edge-relay`.
2. **Rebuild the edge proxy:**
   ```bash
   docker compose build nginx-gateway
   docker compose up -d --no-build --no-deps nginx-gateway
   ```
   The `/edge` routes live in `gateway/entrypoint.sh`, which is built locally rather than
   pulled, so `pull` alone leaves the old entrypoint in place and `/edge` returns 404.
   **Do not** use `docker compose up -d --build nginx-gateway`: `--build` on `up` also
   builds every service with a `build:` section in that service's dependency graph, so it
   replaces the image you just pulled with a local build — verified on a live host, the app
   image then reports `TRELLIS_VERSION=dev` and carries no attestation.
3. Confirm `/healthz` is still `ok: true` with the backend you expect, and that
   **Admin → Edges** renders.
4. Only if you want edges: deploy `deploy/proxy/` on the edge host and enroll a site
   (step-by-step in [proxy.md](proxy.md#enrollment)).

Changes to declare:

- **Compose services:** added `edge-relay`; `nginx-gateway` gained `/edge` routes (rebuild
  required, see step 2). No ports added on the host.
- **`.env` keys:** added, all optional and defaulted (table above).
- **Registry sync:** preserves `managed_by: edge-relay` tools; ignores undecodable edge
  configs instead of pruning them.
- **Tool protocol / `workspace/` layout:** none.
- **Data migrations:** none. etcd gains `<site>__<tool>` entries only when a site enrolls.
- **Image pins:** unchanged (etcd, Redis, Hindsight).

---

### v0.4.1 — 2026-10-21

Documentation-only release. No code, image content, compose service, `.env` key, or registry
behavior changed since `v0.4.0`; the only functional difference is the `TRELLIS_IMAGE` default,
which moves to `v0.4.1`.

It exists because the `v0.4.0` **tag** shipped upgrade instructions telling you to run
`docker compose up -d --build nginx-gateway`. That command builds every service with a
`build:` section in that service's dependency graph, so it does not just rebuild the edge
proxy — it replaces the app image pulled from GHCR with a local build that reports
`TRELLIS_VERSION=dev` and carries no attestation. The fix landed on `main` right after
`v0.4.0`; this tag re-ships it so the instructions you read from the tag are correct.

**If you already upgraded to `v0.4.0`:** nothing is broken. Check what your app image is:

```bash
docker image inspect "${TRELLIS_IMAGE:-ghcr.io/laraibkazi92/trellis-agent-platform:v0.4.0}" \
  --format '{{index .RepoDigests 0}}'
```

- `@sha256:fc37e6c8…` (or any digest that is not the image ID itself) — you are on the released
  image. No action.
- An empty `RepoDigests` or a digest equal to the image ID — that is a local build. Restore
  the released artifact with `docker compose pull && docker compose up -d`, and rebuild the
  proxy with the two-step form:

  ```bash
  docker compose build nginx-gateway
  docker compose up -d --no-build --no-deps nginx-gateway
  ```

**Upgrade from `v0.4.0`:** `docker compose pull && docker compose up -d`, then the two-step
proxy rebuild above if you have not already done it. The `v0.4.0` notes otherwise apply
unchanged.

- **Compose services:** none changed.
- **`.env` keys:** none added or removed.
- **Registry sync / tool protocol / data migrations:** none.
- **Image pins:** `TRELLIS_IMAGE` default → `v0.4.1` (identical image content to `v0.4.0`,
  different build, so it has its own digest and attestation).

---

### v0.5.0 — 2026-10-22

Changes since `v0.4.1`: an edge can now export **MCP servers** over the same outbound
tunnel, caller identity reaches the edge, edge tool/MCP environments are scoped to
declared keys, and credentials can live per user on the edge. The compose files now
default `TRELLIS_IMAGE` to `v0.5.0`, so `docker compose pull && docker compose up -d`
moves an install that does not pin its own tag; if you do pin one, update it (see
[Standard upgrade](#standard-upgrade-published-images)).

Everything is additive for an install that never enrolls an edge, but several behaviour
changes can bite silently. Read all seven under
[Behaviour changes to announce](#behaviour-changes-to-announce); the three most likely to
break an existing deployment are the edge **env allowlist** (undeclared variables stop
being inherited), 4-part edge MCP tool names, and a site that is already `public: true`
now also exposing its MCP tools.

#### Upgrade order: central first, then edges

The wire protocol moves to `proto: 2`. The handshake stays strict, so ordering matters:

| Central | Edge | Result |
| --- | --- | --- |
| v0.5 | v0.4.x | **Supported.** Tools work unchanged; the relay sees `caps=["tools"]`, no MCPs; MCP calls answer `404` |
| v0.4.x | v0.5 | **Clean refusal.** `CLOSE_VERSION` (close code `4001`) at the handshake; the edge logs one terminal "version mismatch — upgrade central first" line and retries only at the maximum backoff (60 s, jittered) |
| v0.5 | v0.5 | Full feature set |

Upgrade **central first**, verify it is healthy, then upgrade edge VMs one at a time. A
v0.5 edge pointed at an old central is not broken silently — it stops at the handshake
and says so — but it does stop serving until central is upgraded.

#### Standard upgrade (published images)

```bash
git fetch --tags
# The compose files default TRELLIS_IMAGE to v0.5.0, so this pulls the release image:
docker compose pull
docker compose up -d
```

If you pin `TRELLIS_IMAGE` in `.env`, repoint it at the new tag (or digest) first —
otherwise you keep running whatever you pinned.

No new nginx route lands in `v0.5.0`: a `v0.4.x` gateway already proxies `/edge`. If you
do rebuild it (for example you are coming from an older tag), use the two-step form:

```bash
docker compose build nginx-gateway
docker compose up -d --no-build --no-deps nginx-gateway
```

**Never `docker compose up -d --build` on a published-image box.** `--build` on `up`
builds every service with a `build:` section in the service's dependency graph, replacing
the image you just pulled with a local build that reports `TRELLIS_VERSION=dev` and
carries no attestation. The two-step proxy rebuild is the supported form, same as
`v0.4.0`/`v0.4.1`.

Building from source (`TRELLIS_IMAGE` unset or overridden) is the one case where
`docker compose up -d --build` is correct.

#### New `proxy.yaml` keys (edge only, all optional)

| Key | Default | Purpose |
| --- | --- | --- |
| `env_passthrough` | `false` | `true` restores the v0.4 denylist env (tunnel token still stripped) |
| `mcps_dir` | `workspace/mcps` | where this edge's `mcp.yaml` files live |
| `export_mcps` | `[]` | allowlist: bare name or mapping `{name, include_tools, exclude_tools, credential_mode, session_ttl_minutes, max_sessions}` |
| `secrets_dir` | `edge-secrets` | shared credential store, `<tool-or-mcp>.env` |
| `user_secrets_dir` | `edge-user-secrets` | per-user store, `<normalized-email>.env` |

`exports` entries also accept the mapping form `{name, credential_mode}` (a bare name
means `shared`). `mcp.yaml` gains `network: allow|none` (default `allow`, stdio only;
`http`/`sse` ignore it). An unknown value warns and falls back to `allow` rather than
dropping the config.

New edge env vars, each an override for the key above: `TRELLIS_EDGE_ENV_PASSTHROUGH`,
`TRELLIS_EDGE_MCPS_DIR`, `TRELLIS_EDGE_SECRETS_DIR`, `TRELLIS_EDGE_USER_SECRETS_DIR`.
No new `.env` keys on central. Values that are not valid are ignored/warn — they never
fail startup.

#### Compose and volume changes

Central: **nothing new**. `edge-relay` and the `/edge` route already exist since
`v0.4.0`; the same service now routes MCP calls.

Edge (`deploy/proxy/docker-compose.yml`): the sample now mounts the three new
directories. If you maintain your own edge compose file, add the equivalents:

```yaml
volumes:
  - ./workspace:/app/workspace
  - ./workspace/mcps:/app/workspace/mcps           # mcps_dir (part of workspace, listed explicitly)
  - ./proxy.yaml:/etc/trellis/proxy.yaml:ro
  - ./edge-secrets:/etc/trellis/edge-secrets       # shared service accounts
  - ./edge-user-secrets:/etc/trellis/edge-user-secrets   # per-user, written by the CLI
```

- Create both credential directories `0700`, owned by `TRELLIS_UID`, before starting.
- The credential stores must live **outside** the sandbox-writable workspace: tool code
  runs as the same uid and can read whatever the workspace exposes, so a per-user store
  inside it hands every caller every other caller's password.
- `mcps_dir` defaults to `workspace/mcps` and is only read at publish time. If the MCP
  manifests are not part of the workspace checkout, point `mcps_dir:` at a separate
  mount instead (`/etc/trellis/mcps`).
- **stdio MCP sessions need a writable sandbox root.** Each session's `HOME`/`TMPDIR`
  lives under it (`mcp-sessions/`), so a `:ro` workspace is fine for tools but not for an
  edge that exports stdio MCP servers.

#### Behaviour changes to announce

1. **Env allowlist (the biggest silent break).** An exported tool or stdio MCP server no
   longer inherits the edge container's environment. It sees a fixed base
   (`PATH`, `HOME`, `LANG`, `TZ`, `TMPDIR`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`,
   `SSL_CERT_FILE`, `LC_*`, `TRELLIS_*`) plus only the keys its `tool.yaml`/`mcp.yaml`
   declares (`secrets`, `optional_secrets`, `variables`, `secret_groups` fields).
   A tool reading an undeclared variable silently sees it unset — declare the key, or set
   `env_passthrough: true` and restart the proxy to restore v0.4 behaviour (minus the
   token; `SIGHUP` cannot apply it).
2. **CA-bundle variables are not in the allowlist.** `REQUESTS_CA_BUNDLE`,
   `CURL_CA_BUNDLE` and `SSL_CERT_DIR` must be declared by any tool/MCP server that needs
   them (only `SSL_CERT_FILE` is always present). A corporate base image that set just
   those will start failing TLS calls after the upgrade.
3. **Edge MCP tool names are 4-part** — `mcp__<site>__<mcp>__<tool>`. An agent that lists
   an edge MCP tool in `allowed_tools` must use that form.
4. **Central MCP names may not contain `__`.** The separator is what distinguishes an
   edge MCP from a central one. Such a name is now rejected when saved (`ValueError`) and
   warned-and-skipped by the registry sync. Rename before upgrading if you wrote one by
   hand.
5. **`public: true` on a site now also exposes its MCP tools.** Site visibility used to
   cover tools only. Review public sites before an edge starts exporting MCP servers.
6. **`SIGHUP` retires every live MCP session.** Credentials for a session are resolved
   once at creation, so the signal is how an edited credential file takes effect without
   waiting out the idle TTL. The next call reopens the session (no error), which costs the
   user one re-login. Tunnel reconnects do **not** retire sessions.
7. **Session directories for email users move once.** They are now keyed by a normalized
   email (`sha256` of the lowercased address), so directories written by a build that
   keyed the raw address are orphaned: those users log in once more. Nothing else reads
   the old directories; they can be deleted.

#### Preparing edge credentials before switching a mode

Default `shared` needs nothing beyond the files. Do these **in order** before setting any
`credential_mode` (per entry in `exports`/`export_mcps`):

1. Create and mount the `secrets_dir` / `user_secrets_dir` volumes (above).
2. Populate the shared file for each exported tool or MCP server —
   `<secrets_dir>/<tool-or-mcp>.env`, mode `0600`:
   ```bash
   install -m 600 /dev/null ./edge-secrets/devops-cli.env   # then edit it
   ```
3. Provision each operator who will use a `per_user`/`per_user_required` entry:
   ```bash
   docker compose exec -T trellis-proxy \
     python core/proxy.py user-secrets set ops@example.com \
     --config /etc/trellis/proxy.yaml <<'EOF'
   DEVOPS_USERNAME=ops
   DEVOPS_PASSWORD=...
   EOF
   ```
4. **Then** set `credential_mode` and `SIGHUP`. Switching to `per_user_required` before
   step 3 makes every call for an unprovisioned user fail closed with
   `no credentials for <email> on edge <site>`.

`user-secrets list` prints key names only, so it is safe to paste into a ticket. Verify
with `SIGHUP` and one real call per user; credentials never cross the tunnel, so nothing
appears centrally to check.

#### Enabling MCP export

Add `export_mcps:` to the edge's `proxy.yaml` and `SIGHUP` — the catalog republishes
without a restart (a stdio server with no static `tools:` block is discovered live, 20 s
per server, concurrently). Verify in **Admin → Edges**: the site shows `proto 2`, the
`mcp` capability badge, and one row per server. If a server is missing, the edge log names
it — the usual causes are a name colliding with a central MCP, an oversized schema, or a
hello frame over the 10 MiB cap (the largest catalogs are dropped, tools stay online).

#### Node MCP servers and sandbox limits

Set `SANDBOX_RLIMIT_AS_MB=8192` for stdio MCP servers written in Node — the `4096`
default is tight and an allocation failure looks like a crash. `SANDBOX_RLIMIT_CPU_S`
counts **consumed** CPU, so the 600 s default does not retire an idle long-lived session.
Both variables were removed in `v0.7.1`; size a session container with the manifest's
`limits:` block instead ([mcp.md → Memory sizing](mcp.md#memory-sizing-sessions--limitsmemory_mb--60--of-host-ram)).

#### Rollback

- **Revert central to `v0.4.x`:** v0.5 edges stop at the handshake (`CLOSE_VERSION`). That
  is safe and visible; their tools go offline until central is restored. Nothing on the
  edge is corrupted.
- **Revert only the edges:** central keeps serving, including its tools. A reverted edge
  advertises `caps=["tools"]`, and central **keeps** the leftover `/registry/mcps/*`
  entries rather than pruning them on an empty catalog, so agents that list
  `allowed_mcps: ["<site>__<mcp>"]` still see those tools but every call answers the
  `404` from the failure table. They are pruned by the next v0.5 publish from that site.
- **Restoring central while edges are newer** is the safer direction; the reverse
  (old central, new edge) is the one that refuses.

Changes to declare:

- **Compose services:** none added or removed on central. Edge compose gains volumes for
  `mcps_dir`, `secrets_dir`, `user_secrets_dir`.
- **`.env` keys:** none added centrally. Edge gains four `TRELLIS_EDGE_*` overrides
  (optional); `SANDBOX_RLIMIT_AS_MB=8192` recommended for Node MCP servers.
- **Registry sync:** `/registry/mcps/` is preserved for `managed_by: edge-relay` entries,
  like `/registry/tools/`; a reference to a not-yet-connected edge warns instead of
  failing.
- **Tool protocol / `workspace/` layout:** unchanged. `mcp.yaml` gains optional
  `network:`; `proxy.yaml` gains five keys; edge MCP tool names are 4-part.
- **Data migrations:** none in etcd. One-time move of edge MCP session directories for
  email users (one re-login).
- **Image pins:** `TRELLIS_IMAGE` default moves `v0.4.1` → `v0.5.0` in `docker-compose.yml`,
  `.env.example` and both egress compose files. If you pin a tag or digest in `.env`,
  update it yourself — the default only applies when `TRELLIS_IMAGE` is unset.

---

### v0.5.1 — 2026-10-22

Two fixes on top of `v0.5.0`. No compose service, `.env` key, wire-protocol or registry
schema changed; `TRELLIS_IMAGE` default moves to `v0.5.1`.

- **A pruned MCP no longer leaves ghost search hits.** `delete_mcp_tool_embeddings` built the
  prefix `.../mcp__<server>__/embedding`, which matches no real key (they end
  `.../mcp__<server>__<tool>/embedding`), so a pruned central MCP's tool vectors survived and
  kept ranking in tool search as calls that fail. It now deletes exactly the `/embedding`
  keys under the server's name prefix. Nothing extra to run: the next prune deletes cleanly.
  Vectors orphaned by a prune **before** this release are not rediscovered automatically —
  if tool search still shows a server you deleted, clear that server's range once (only its
  embeddings live there; the config is already gone):

  ```bash
  docker compose exec etcd etcdctl del --prefix "/registry/tools/mcp__<server>__"
  ```

- **A reference name may no longer end in `_`.** `a___b` splits two ways, so a trailing
  underscore leaves no unambiguous `<site>__<tool>` / `mcp__<server>__<tool>` form.
  `save_mcp_config` refuses it for any MCP, `save_tool_config` for edge (`managed_by:
  edge-relay`) keys, db-sync skips that one MCP manifest with a warning instead of failing
  the run, Admin → Edges rejects a site id ending in `_`, and the relay skips such an entry
  published by an older edge. A **central tool** is addressed by its bare name, so a trailing
  `_` stays legal there and an existing workspace is unaffected.

- **Image pins:** `TRELLIS_IMAGE` default → `v0.5.1` in `docker-compose.yml`, `.env.example`
  and both egress compose files.

---

### v0.6.0 — 2026-10-23

Changes since `v0.5.1`: **execution isolation, phase 1**. Every local tool call now
runs in its own gVisor (`runsc`) container, created by a new `runner` service from the
tool's manifest — the hub no longer forks tool subprocesses. Network access becomes a
deny-by-default profile (`none` / `internal` / `internet`) and per-container resources
come from a `limits:` block instead of helper rlimits. The shipped compose default moves
to `SANDBOX_BACKEND=container`, and `TRELLIS_IMAGE` to `v0.6.0`.

This section covers all four phases, including the edge-sealed per-user credentials
added in phase 4 (see "Per-user credentials and the edge key" in `docs/proxy.md`).

#### Breaking: the agent allowlist is now enforced server-side

The agent runtime mints a short-lived HMAC token per run (`AGENT_TOKEN_SECRET`, at least
32 bytes, on `host`, `hub`, `edge-relay`, `gateway`, `taskiq-worker` and both `runner`
services; the edge proxy needs the same value). The hub, the relay and the runner verify it and resolve the
agent's `allowed_tools`/`allowed_mcps` themselves. A call with no token, a forged token,
an expired token, or a tool outside the agent's allowlist is refused with
`access_denied`, even if the caller is the framework itself.

- `ENFORCE_AGENT_TOKENS` is `enforce` in the shipped compose. `log` records every
  would-be denial and still runs the call (one rollout window); `off` skips the check.
- `AGENT_TOKEN_SECRET` is a `;`-separated list: the first value signs, every value
  verifies. Rotate by prepending the new key, deploying, then removing the old one.
- Tokens live 15 minutes by default and there is no revocation list. A leaked token ages
  out; a leaked *key* means rotating `AGENT_TOKEN_SECRET` everywhere.
- The `gateway` principal may call tools directly (its own whitelist search governs which
  tools it surfaces); it is not subject to an agent's allowlist.
- Agent configs do not change: `allowed_tools` / `allowed_mcps` keep their existing
  syntax and wildcards (`<site>__*`) now expand against the live registry per call.

#### Before you upgrade: install, register, and prove gVisor

The runner fails closed when `runsc` is missing or cannot start a trivial container:
there is no fallback to `runc`. On such a host, chat-only agents keep working and every
tool call reports `sandbox_unavailable`.

1. Install `runsc` on every host that runs a `runner` (central and each edge), pinned to a
   version you have tested. On x86_64 (`arm64/` on arm hosts):

   ```bash
   curl -fsSLO https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/runsc
   curl -fsSLO https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/runsc.sha512
   sha512sum -c runsc.sha512 && chmod +x runsc
   sudo install -m 0755 runsc /usr/bin/runsc
   ```

2. Register it in `/etc/docker/daemon.json`, keeping every existing key:

   ```json
   {
     "runtimes": {
       "runsc": {
         "path": "/usr/bin/runsc",
         "runtimeArgs": ["--network=sandbox"]
       }
     }
   }
   ```

   Restart Docker. `--network=sandbox` keeps traffic in gVisor's netstack so the
   `DOCKER-USER` profile rules apply to it. Do **not** add `--ignore-cgroups=true`: the
   `limits:` block needs cgroups.

3. Prove it before starting the stack:

   ```bash
   docker info --format '{{json .Runtimes}}' | grep runsc
   docker run --rm --runtime=runsc hello-world
   ```

   Both must succeed. A per-tool `container_runtime: runc` is the escape hatch for code
   gVisor cannot run; it forfeits kernel-syscall isolation and needs a reason per tool.
   Full detail: [deploy.md → Prerequisite: gVisor](deploy.md#prerequisite-gvisor-runsc).

#### New service: `runner` (socket-only API)

`runner` starts on central and on each edge. It is the **only** service that mounts
`/var/run/docker.sock`; do not mount that socket anywhere else — access to it is root on
the host.

- **API:** a Unix socket at `/run/trellis/runner.sock`, shared through the `runner-run`
  volume with `host`, `hub`, `gateway` and `taskiq-worker`. It never listens on TCP, and
  the runner's own `network_mode: none` means no tool container can reach it.
- **Auth:** `RUNNER_TOKEN` is required and must be identical on the runner and every
  caller (`openssl rand -hex 32`). Only `DEV_MODE=true` skips it, with a warning.
- **Posture:** one process on purpose (container slots live in memory) — do not scale it
  to two replicas. It runs as root only to open the Docker socket; every container it
  starts runs as `${TRELLIS_UID}:${TRELLIS_GID}`.
- **Startup gates:** runtime registered *and* a trivial container starts, `RUNNER_IMAGE`
  exists locally (it never pulls), the required profile networks exist, and a host-path
  canary passes. `python scripts/runner_preflight.py` reports the same gates.

`TRELLIS_HOST_WORKSPACE` must be the **host** path of the workspace directory, not
`/app/workspace`. Docker resolves every tool bind mount against the host filesystem, and
a wrong value refuses to serve with:

```text
TRELLIS_HOST_WORKSPACE='/app/workspace' must be the HOST path of the workspace (the
directory that is mounted at /app/workspace inside the runner); pointing it at a
container path makes every bind mount resolve to the wrong files.
```

#### Firewall and network profiles

The two tool networks need pinned subnets and are created outside compose. Run once per
host, as root:

```bash
sudo scripts/setup-network-profiles.sh            # networks + DOCKER-USER rules (idempotent)
sudo scripts/setup-network-profiles.sh --verify   # exit non-zero if a rule/network is missing
```

`--verify` is the gate: the runner checks the networks at startup, and provisioning
should run the rule check before `docker compose up -d`. Re-run it after a reboot, a
firewall reload, or a Docker upgrade — Docker recreates `DOCKER-USER` empty.

`TRELLIS_INTERNAL_CIDRS` (comma-separated) is the allowlist for `network: internal`
tools. That profile is what makes **SSH** work: SSH is L3 traffic, so adding the
destination CIDR is enough. Cloud-metadata addresses are dropped from *every* profile,
and `TRELLIS_ENGINE_SUBNETS` lists the compose network CIDRs that are dropped too (set it
when your compose subnet is not the default). The profiles, both variables and the setup
script were removed in `v0.7.1`: see [v0.7.1](#v071-2026-10-26) and
[deploy.md → Network policy](deploy.md#network-policy).

#### Breaking: `network` default flips to `none`

`tool.yaml` and `mcp.yaml` now default to `none`; legacy `allow` still parses and means
`internet`. Audit your manifests before upgrading:

```bash
grep -L '^network:' workspace/tools/*/tool.yaml workspace/mcps/*/mcp.yaml
```

Every file this prints has no egress after the upgrade. If the tool calls a public API it
now fails on name resolution or `ENETUNREACH` from inside its container and needs
`network: internet`. A tool reaching an internal API or SSH host needs
`network: internal` plus its CIDR in `TRELLIS_INTERNAL_CIDRS`. `none` blocks loopback
too. An unrecognized value now warns and becomes `none` (v0.5 fell back to `allow`).

#### Breaking: `SANDBOX_RLIMIT_*` are inert; use `limits:`

With `SANDBOX_BACKEND=container` the Landlock helper — and its rlimits — never runs.
Per-container cgroup v2 limits come from the manifest instead:

| v0.5 environment variable | v0.6 replacement | Note |
| --- | --- | --- |
| `SANDBOX_RLIMIT_AS_MB` | `limits.memory_mb` | cgroup `--memory`, not an address-space rlimit |
| `SANDBOX_RLIMIT_CPU_S` | `limits.cpus` | a rate quota, not consumed-CPU seconds |
| `SANDBOX_RLIMIT_NPROC` | `limits.pids` | cgroup `--pids-limit` |
| `SANDBOX_RLIMIT_FSIZE_MB` | — | no per-file cap; `limits.tmpfs_mb` bounds `/tmp` |

Defaults (all overridable per tool and per MCP server):

| `limits:` field | Default | Range |
| --- | --- | --- |
| `memory_mb` | `512` | 32–65536 |
| `cpus` | `1.0` | >0–64 |
| `pids` | `256` | 16–32768 |
| `tmpfs_mb` | `128` | 1–32768, and ≤ `memory_mb / 2` |

The tmpfs is charged to the container's cgroup, so `tmpfs_mb > memory_mb / 2` is
rejected rather than becoming an OOM kill on the first temp file. Size the host as
`RUNNER_MAX_CONTAINERS × typical memory_mb × 1.5` (gVisor overhead is counted in the
cgroup). Keep the old variables only for a local `auto`/`bwrap`/`landlock` install.

#### New manifest fields

All optional, so an existing `tool.yaml` keeps working; the defaults are the conservative
ones.

```yaml
- name: issues_create_ticket
  # ... required fields ...
  network: internal               # none (default) | internal | internet; `allow` == internet
  container_runtime: runsc        # runsc (default) | runsc-variant | runc
  output_dirs: [reports]          # subset of [reports, output]
  limits:
    memory_mb: 1024
    cpus: 1.5
    pids: 512
    tmpfs_mb: 256                 # <= memory_mb / 2
  image: null                     # reserved; v0.6 ignores it
```

`output_dirs` grants the calling agent's `reports/<agent>` or `output/<agent>` read-write.
Only that directory is mounted; the suite and `shared/` stay read-only and no other suite
is visible. The mount is only created when the call carries an agent identity.

#### New `.env` keys

| Key | Needed by | Purpose |
| --- | --- | --- |
| `SANDBOX_BACKEND` | hub, edge proxy | `container` (shipped default); `auto`/`bwrap`/`landlock` for local dev |
| `RUNNER_TOKEN` | runner + `host`/`hub`/`gateway`/`taskiq-worker` | required bearer for the control socket |
| `RUNNER_SOCKET` | runner + callers | UDS path shared through `runner-run` |
| `TRELLIS_HOST_WORKSPACE` | runner | **host** path of the workspace |
| `CONTAINER_DEFAULT_RUNTIME` | runner | `runsc` unless a manifest overrides it |
| `RUNNER_IMAGE` | runner | image tool containers start from; must exist locally, and must be v0.7.1 or newer |
| `RUNNER_MAX_CONTAINERS` / `RUNNER_MAX_CONTAINERS_PER_TOOL` | runner | capacity; excess returns `429` |
| `RUNNER_REAP_INTERVAL_S` | runner | canary/orphan sweep interval |
| `TOOLS_NET_INTERNAL_SUBNET` / `TOOLS_NET_INTERNET_SUBNET` | runner + setup script | pinned profile subnets |
| `TRELLIS_INTERNAL_CIDRS` | setup script + runner | what `internal` may reach |
| `TRELLIS_ENGINE_SUBNETS` | setup script | compose CIDRs dropped from every profile |
| `DOCKER_GID` | runner | docker group for the socket |
| `TRELLIS_INSTALL_ID` | runner | `trellis.install` label on every container |

Defaults and full comments are in `.env.example`, section *Execution Isolation Runner
(v0.6)*. Compose refuses to start while `RUNNER_TOKEN` or `TRELLIS_HOST_WORKSPACE` is
empty.

#### Breaking: `FRAMEWORK_API_URL` / `FRAMEWORK_EXECUTION_TOKEN` are gone

Neither variable is injected into a tool environment any more (audited: no in-tree tool
read them). A tool that must call back into the framework gets a credential through its
manifest `secrets:` and must not assume it is loopback-privileged: `network: none` has no
loopback, and `internal`/`internet` drop the engine's own networks.

#### Phase 2: MCP sessions, discovery and `execute` in containers

MCP servers are no longer children of `host`/`trellis-proxy`, and the agent's shell is no
longer a child of `host`. Three behaviour changes to know before you upgrade:

1. **`mcp-sessions/` is dead state — delete it.** Session `HOME` directories used to live
   under the sandbox writable root (`/app/workspace/mcp-sessions/` on central,
   `${SANDBOX_RW_PATH}/mcp-sessions/` on an edge). A session now runs in a runner
   container whose `HOME`/`TMPDIR` are that container's tmpfs, so the directory is never
   read or written again. It still contains old login state (credentials the server
   cached); remove it after upgrading. The proxy logs one warning at startup if it finds
   one.
2. **Central `stdio` MCPs now run in runner session containers.** `host`, `gateway` and
   `taskiq-worker` must be on the `runner-run` volume and have `RUNNER_TOKEN`/`RUNNER_SOCKET`
   like `hub` already does; without a reachable runner, central MCP tools fail with
   `mcp_session_lost` and every non-MCP tool keeps working. Only the manifest's declared
   env keys are sent (the runner rejects anything else), and the process-environment merge
   that used to surround them is gone. Discovery opens a throwaway container
   (`kind="discovery"`, 60 s) instead of spawning a process in `host`.
3. **`execute` and the console file tools are scoped differently.** `execute` runs
   `bash -lc <cmd>` in a throwaway container (`network none`, empty `/workspace`), so a
   command that relied on reading the framework's filesystem or the workspace tree no
   longer can. `ls`/`read_file`/`write_file`/`edit_file`/`glob`/`grep` stay in-process but
   are rooted at `reports/<agent>` (central: `${WORKSPACE_ROOT:-/app/workspace}/reports/<agent>`)
   instead of `/workspace`. Agents writing to other paths must use a tool, not the console.

Session semantics are otherwise unchanged on an edge: same identity key, TTL, caps, LRU,
tombstones and never-replay. New: `MAX_SESSIONS_EDGE` is read from the environment
(default 32) and now bounds *containers*, so size it against `limits.memory_mb` — see
[mcp.md → Memory sizing](mcp.md#memory-sizing-sessions--limitsmemory_mb--60--of-host-ram).
A runner restart drops every warm session: the next call returns `mcp_session_lost` once
and a fresh container starts after it.

#### Breaking: per-user plaintext credentials and `user-secrets` are removed

Per-user credentials for edge tools and MCP servers are now **browser-sealed**: the user
enters them in central (Configuration → Edge credentials), the browser encrypts them to the
edge's public key, and central stores only the envelope. The edge decrypts with a private
key that never leaves the VM. Consequences for an existing install:

1. **Delete `edge-user-secrets/` (after users re-enter their sets).** The directory and
   `proxy.yaml`'s `user_secrets_dir` key are gone; the value is ignored (one startup
   warning names the leftover directory). `TRELLIS_EDGE_USER_SECRETS_DIR` is no longer
   read. Remove the compose mount
   (`- ./edge-user-secrets:/etc/trellis/edge-user-secrets`).
2. **`trellis-proxy user-secrets` is gone.** `set`, `list` and `delete` are unknown
   commands, not deprecated aliases. There is no CLI replacement: a user seals a set
   themselves in the UI (or clears it from the same form). The shared
   `edge-secrets/<item>.env` store is unchanged and still works exactly as before.
3. **Generate the edge key and mount it.** On each edge host:

   ```bash
   install -d -m 0700 edge-keys
   docker run --rm -v "$PWD":/w -e EDGE_PRIVATE_KEY_PATH=/w/edge-keys/edge-key \
     ghcr.io/laraibkazi92/trellis-agent-platform:v0.6.0 \
     python core/proxy.py edge-keygen --path /w/edge-keys/edge-key
   sudo chown -R "${TRELLIS_UID:-1000}:${TRELLIS_GID:-1000}" edge-keys
   ```

   then add to `deploy/proxy/docker-compose.yml` (the shipped file already has it):

   ```yaml
       environment:
         EDGE_PRIVATE_KEY_PATH: /etc/trellis/keys/edge-key
       volumes:
         # The DIRECTORY: the rotation overlap needs edge-key.old beside edge-key.
         - ./edge-keys:/etc/trellis/keys:ro   # trellis-proxy ONLY, never runner
   ```

   The proxy must run `sandbox: container` (the v0.6 default). A legacy backend
   (`auto|bwrap|landlock`) mounts the whole filesystem into the tool process, which would
   expose this key; sealed calls are refused while one is configured.

   The loader refuses a file with a mode wider than `0400`, a non-RSA key, or a path
   inside the workspace. **Keep `/etc/trellis/keys/edge-key` in the host backup**: losing it
   means every user re-enters their set.
4. **Re-enter per-user credentials.** After the key is mounted and the new proxy has
   connected (its fingerprint appears in Admin → Edges), each user opens the target's
   credential form and seals the declared secret keys. Until then a
   `credential_mode: per_user_required` target fails closed with `missing_credentials`; a
   `per_user` target uses the shared account.
5. **Rotation is an overlap, and it needs a SIGHUP.** `edge-keygen --rotate` keeps
   `edge-key.old`; send `SIGHUP` (or restart) so the running proxy reloads the key and
   republishes the new fingerprints before users seal to it. Blobs sealed to the old key
   still open until `--drop-old-key`. After that, the affected records show
   "re-enter credentials (edge key rotated)". Central's write endpoint accepts a blob only
   for the current or previous key.

Resolution rules are stricter than v0.5 and are deliberate: a sealed set is
**all-or-nothing** for secrets (no shared fallback for a missing key) and `variables`
(endpoints) are never taken from per-user material. That fixes the v0.5 behaviour where a
partial per-user file silently completed itself from the shared account.

Rollback is not available for this phase: old proxy images read `edge-user-secrets/` only,
and the directory will have been deleted. Keep a copy until every edge is on v0.6.0.

#### Rollback

`SANDBOX_BACKEND=auto` restores the in-process bwrap/Landlock path (uncomment the hub's
legacy `security_opt` lines for bwrap). The `runner` service stays in the compose file,
idle. There is no etcd or workspace migration to undo — the new manifest fields are
optional.

Two caveats:

- Rollback restores the *process* sandbox, not the old network default: a manifest that
  omits `network:` is still `none` on the legacy path, so an egressing tool needs
  `network: internet` either way.
- That path is for development hosts only. It reintroduces the shared-uid, writable-root
  posture that v0.6 exists to remove.

Changes to declare:

- **Compose services:** added `runner` (central and edge) with the shared `runner-run`
  volume; nothing else gains the Docker socket.
- **`.env` keys:** added (table above); `RUNNER_TOKEN` and `TRELLIS_HOST_WORKSPACE` are
  required.
- **Registry sync:** none; manifests are still read from `workspace/`, and the new
  `network`/`limits`/`output_dirs`/`container_runtime` fields parse as optional.
- **Edge credentials:** `edge-user-secrets/` and `user-secrets` are removed; a sealed
  per-user set is re-entered in the UI and `edge-key` must be generated and backed up
  (breaking section above).
- **Tool protocol / `workspace/` layout:** stdin/stdout and `TRELLIS_USER_*` unchanged;
  the visible filesystem inside a tool shrinks to the suite, `shared/` and a declared
  output dir.
- **Data migrations:** none.
- **Image pins:** `TRELLIS_IMAGE` default → `v0.6.0` in `docker-compose.yml`,
  `.env.example` and both egress compose files.

### v0.6.1 — 2026-10-25

**Fix:** `/configuration` and `/admin/configuration` no longer throw
`TypeError: Cannot set properties of null (setting 'innerHTML')` on a page with no
configuration keys. The shared search/pagination script dereferenced
`#pagination-controls`, which both templates render only when there are items. The same
empty page also claimed "No configuration keys match your search" when nothing had been
searched; that message now appears only when a filter removes every item, and typing in
the search box on an empty page no longer re-throws.

The release also adds a parse-only test that compiles every template
(`tests/test_templates.py`), after a literal Jinja tag inside a JavaScript comment 500'd
the page in the first attempt at this fix.

Changes to declare:

- **Compose services / `.env` keys / registry / data:** none.
- **Image pins:** `TRELLIS_IMAGE` default → `v0.6.1` in `docker-compose.yml`,
  `.env.example` and both egress compose files.

---

### v0.7.0 — 2026-10-26

Changes since `v0.6.1`: durable run history, LLM latency metrics, declarative
guardrails, default-deny tool authorization, and lazy edge tool catalogs. The four new
gates default to off (`tool_authz_mode`, `bound_tools_mode`, `hub_call_mode`,
`lazy_catalog`), so nothing is enforced until an operator promotes it — but guardrails,
orphan reaping and run-subtree pruning are **not** switched off, and they change behaviour
on upgrade (see **Guardrails** and **Data migrations** below). The `TRELLIS_IMAGE` default
moves to `v0.7.0`.

#### Feature set

- **Hash-chained run event log + live heartbeat.** Every workflow run (script and agent)
  appends `run_enqueued`, `run_started`, `run_completed`, `run_failed`, `run_cancelled`,
  `run_orphaned` and `run_retried` to `/runs/{agent}/{run_id}/events/{seq:08d}`, each entry
  carrying the previous digest, with the chain head on the run record. A heartbeat key is
  rewritten every 15 s while the run executes. The Workflows page shows a per-run timeline
  with a `CHAIN OK` / `CHAIN BROKEN @ seq N` badge, served by
  `GET /workflows/{agent}/runs/{run_id}/events`.
- **Orphan reaper + bounded whole-run retry.** A scheduled task (`*/2 * * * *`) fails runs
  that a dead worker left behind, and optionally re-enqueues them **whole** under a new
  `run_id`. No mid-run resume and no checkpointing. Retries are opt-in per workflow
  (`config.yaml → retries: {max_attempts, backoff_s}`, default `1` / `60 s`, i.e. no retry)
  and apply **only** to runs the reaper orphaned — a run that failed for any other reason is
  never retried. The retried prompt is the stored copy, truncated to 8 KiB. The staleness
  windows are tunables: `REAPER_STALE_HEARTBEAT_S` (90), `REAPER_STALE_PENDING_S` (300),
  `REAPER_STALE_PROCESSING_S` (3600).
- **LLM latency metrics with provider rollups.** Each call records end-to-end latency (and
  first-observable-event time when streaming) into `/metrics/agents/{agent}` and
  `/metrics/providers/{provider}`; the LLM Providers page shows TTFT and total p50/p95 plus
  an error rate, the Agents page a per-agent `p50 / p95 / err` line. Recording is
  fire-and-forget — a metrics failure never breaks a response.
- **Declarative regex guardrails (v1).** Per-agent and per-workflow `on_input` / `on_output`
  rules, plus framework-wide defaults, with `block` and `redact` actions.
- **Default-deny tool-boundary authorization, staged.** One policy document gates tool
  discovery and invocation; rollout is per surface, `off → shadow → enforcing`.
- **Lazy edge tool catalogs + `describe_tool`.** An edge can publish tool names and short
  summaries only, with full schemas fetched on demand over the tunnel and cached centrally.

#### Tool authorization: three switches, all `off`

Admin → **Tool Authorization** (`/admin/tool-authz`). One policy document
(`/registry/tool_policies`), one evaluator, one shared deny ring, three rollout switches.
In every evaluating mode a call with **no matching rule is denied**.

| Switch | etcd key | Gates |
| --- | --- | --- |
| **Mode** | `/config/framework/tool_authz_mode` | `use_tool` (gateway and supervisor/agent) and `search_tools` |
| **Bound tools** | `/config/framework/bound_tools_mode` | tools an agent lists in `allowed_tools` / `allowed_mcps` |
| **Direct hub calls** | `/config/framework/hub_call_mode` | every call the hub dispatches, local or to an edge |

| Value | Behaviour |
| --- | --- |
| `off` (default; also what an absent key means) | No evaluation. Identical to `v0.6.1`. |
| `shadow` | Evaluates and records would-be denials in the ring, still allows the call. |
| `enforcing` | Denies unmatched calls; tools do not run. |

**A fresh install does nothing until an operator promotes a switch.** All three keys are
absent after the upgrade, which means `off`.

- **Promote in this order: `use_tool` → bound tools → direct hub calls.** The last switch
  sits on the hub's last mile, so it re-checks traffic the other two already let through;
  promoting it to `enforcing` denies agent calls with no matching rule *regardless of* the
  other two modes. Settle and soak the first two before touching it.
- **`enforcing` needs a coverage pass first.** **Bootstrap** on the policy page generates
  the initial document from the current public whitelist: one rule per public tool with
  `allow_principals: ["*"]`, plus one rule per agent covering every tool it binds directly,
  granted to `agent:<name>` / `workflow:<name>`. Bootstrap **replaces the whole document**,
  so re-running it resets hand-written tightening. Before flipping a surface, run it in
  `shadow` under real traffic and reconcile every entry in the deny table.
- **A `*` (public) rule masks a missing per-agent rule**, so a deny probe must use a
  non-public tool; probing with a public tool proves nothing. The table's `surface` column
  tells you which switch recorded an entry, and all three share one 200-entry ring — soak
  one surface at a time.
- Denials keep the existing shapes: the `SYSTEM: Access denied…` string for agent-side
  calls, `SYSTEM: Access denied. Tool '<name>' is not permitted for this principal.` as a
  tool-error dict from the hub. Deny log lines carry the principal, tool, scope and mode —
  never tool arguments.
- **Rollback is immediate:** set the mode back to `shadow` (or `off`). The etcd watch
  invalidates every process's cache without a restart.
- A mode key holding an unrecognised value **fails closed to `enforcing`**, so a typo does
  not silently disable a gate you already promoted. The one exception is a cold process
  that has **never** read a policy: if that first read fails (etcd unreachable at startup)
  the gate evaluates nothing and allows calls for ~5 s per process until a read succeeds,
  so watch the deny log for the first minutes after a deploy.
- **Scope:** console tools (`ls`, `read_file`, …), A2A/subagent delegation and admin tools
  are framework capabilities, not hub tools, and stay outside the policy.

#### `OIDC_GROUPS_CLAIM` and `group:` membership

`OIDC_GROUPS_CLAIM` (optional, default `groups`) names the identity-provider claim that
`group:` rules match. The OIDC callback reads it from the validated **ID token** and stores
the result as `groups` on the user record — never in the session cookie. The claim may be a
list or a **comma**-separated string; spaces are part of a name, never a separator (a group
called `All Staff` stays one group).

- **An absent or malformed claim means "no groups"**; it never fails a login. For OIDC the
  claim must be present in the **ID token** — the framework does not call the userinfo
  endpoint. Check **Your resolved groups** on the tool-authorization page after logging in.
- The claim is **unioned with** `/config/framework/principal_groups`, a manual mapping that
  can add a group but cannot revoke one the IdP asserted. Both are additive; an install that
  sets neither behaves exactly as before.
- **Groups refresh at login only**, and API-key traffic never re-authenticates through the
  IdP — a user removed from a group at the IdP keeps the grant until their next login.
- **Background runs have no request context** and resolve to `workflow:<name>`, which has no
  stored user record: IdP groups never apply there. Only `/config/framework/principal_groups`
  can grant a workflow a group.

#### Guardrails (agents and workflows)

`config.yaml` gains an optional block, identical for user agents, `background_agent` and
`background_script` workflows:

```yaml
guardrails:
  on_input:
    - type: deny_patterns
      name: no_secrets
      patterns: ["AKIA[0-9A-Z]{16}"]
      action: block          # block | redact
  on_output:
    - type: deny_patterns
      name: pii_email
      patterns: ["[\\w.+-]+@[\\w-]+\\.[\\w.]+"]
      action: redact
    - type: max_chars
      value: 8000            # input over the limit blocks; output truncates with a marker
```

Framework-wide rules live at `/config/framework/guardrails_defaults` in the same
`on_input` / `on_output` shape. They are merged **first**, the agent's or workflow's own
rules appended, and cached for 30 seconds. There is no admin UI for the framework defaults —
set them through etcd. An interactive input block returns HTTP `400` naming the rule;
an output block replaces the reply with a `SYSTEM:` notice and redaction rewrites it before
it is stored or returned. Hits are counted in the agent's metrics doc and shown as a
`GUARDRAIL` badge. A malformed rule is skipped and logged (fail-open); there is no runtime
timeout on a regex, so keep admin-authored patterns simple.

**Behaviour change — the one that can break an existing workflow.** A `background_script`
run's rendered trigger payload is now evaluated **before** the script is spawned. A blocking
rule fails the run (`guardrail blocked input`, `run_failed` event with
`error_type: GuardrailBlocked`) and the process never executes; a `redact` rule rewrites the
payload the script reads from `stdin`. Scripts parse that payload as machine input, so prefer
`block` there. Framework defaults apply to scripts too, so a workflow with no `guardrails`
key of its own is **not** exempt. Note also that the registry sync stores `config.yaml`
verbatim: a workflow that already carries an inert `guardrails:` block becomes active on
this deploy. Check `workspace/workflows/*/config.yaml` before upgrading.

Guardrails are a filter on what a run consumes and returns, not a vault: a run's prompt is
written to `/runs/{agent}/{run_id}` at `processing` **before** the input rules run, and an
input redaction only rewrites what a script receives on `stdin`. If the payload carries a
credential you must not persist, block it rather than redact it, and keep such values out of
`.env`-injected tool secrets.

Known v1 gaps, unchanged by the above: a script's `stdout` is not inspected, streaming
replies are checked only after the full output is assembled, and supervisor-delegated
sub-agent turns are not checked.

#### Lazy edge catalogs: opt-in and relay-version bound

`proxy.yaml` gains `lazy_catalog` (default `false`, live on `SIGHUP`). With it on, the edge
publishes tool names and summaries only (≤120 characters, no argument schemas) and the relay
fetches a full schema on demand over the tunnel, caches it in the registry, and re-indexes
the embeddings. Callers get the schema through the new `describe_tool` tool, agent-side and
on `/mcp`.

- **The central relay must be `v0.7` or newer.** A `v0.6.1` relay rejects the capability at
  the handshake (`CLOSE_MALFORMED`) and the edge keeps retrying; there is no automatic
  downgrade-republish. Leave the flag off until central is upgraded, and flip it off on the
  edge if you must roll back before upgrading central.
- A lazy tool must be described before it is called with arguments: `describe_tool` first,
  then `use_tool`.
- Degradation is explicit: with the edge offline, a describe serves the cached schema if one
  exists and an `unavailable` marker otherwise, and never blocks tool execution.

#### Upgrade actions

1. `docker compose pull && docker compose up -d` — or `docker compose up -d --build` if you
   build from source. Nothing else is required; the four new gates stay off.
2. If you want any of the new controls: set `OIDC_GROUPS_CLAIM` if your IdP does not use
   `groups`, then work through the tool-authorization promotion order above, and enable
   `lazy_catalog` on edges only after central is on `v0.7.0`.

**Upgrading from `v0.5.x`:** read the `v0.6.0` section first. `RUNNER_TOKEN`,
`AGENT_TOKEN_SECRET` and `TRELLIS_HOST_WORKSPACE` are required (compose refuses to start
while they are empty); that has been true since `v0.6.0` and is unchanged in `v0.7.0`.

Changes to declare:

- **Compose services:** none. No service, port, volume, capability or healthcheck changed.
- **`.env` keys:** added `OIDC_GROUPS_CLAIM` (optional, default `groups`). No key renamed or
  removed; all tool-authorization, guardrail and catalog controls live in etcd or
  `proxy.yaml`, not in `.env`.
- **Registry sync:** none. `guardrails` and `retries` live inside `config.yaml`, which the
  sync already stores verbatim.
- **Tool protocol / `workspace/` layout:** none — `stdin` JSON in, `stdout` JSON out, and the
  directory layout are unchanged. The edge tunnel gains a `lazy_catalog` capability and two
  detail frames, both inert unless an edge sets `lazy_catalog: true`.
- **Data migrations:** none. etcd gains additive key families created on first write —
  run event/heartbeat keys, `/metrics/agents/*` and `/metrics/providers/*`,
  `/registry/tool_policies`, `/registry/tool_authz_denies`,
  `/config/framework/{tool_authz_mode,bound_tools_mode,hub_call_mode,guardrails_defaults,principal_groups}`
  — plus a `groups` field on user records at the next login. Existing users, keys, agent
  configs and run history are untouched. Two changes to be aware of: hourly pruning now
  deletes a run's whole subtree (state, events, heartbeat), and the reaper will mark runs
  that were **already** stuck in `processing` or `pending` before the upgrade as `failed`
  once they pass its staleness window (raise `REAPER_STALE_PENDING_S` /
  `REAPER_STALE_PROCESSING_S` before upgrading if a long backlog is legitimate).
- **Image pins:** `TRELLIS_IMAGE` default → `v0.7.0` in `docker-compose.yml`,
  `.env.example`, `docker-compose.egress.yml` and `docker-compose.egress-ci.yml` (the same
  tag appears in the commented `RUNNER_IMAGE` example in `.env.example`).

---

## Release checklist (maintainer template)

Copy this into the release PR/notes and fill it in per release.

```markdown
### vX.Y.Z — YYYY-MM-DD

- [ ] Tag created: `vX.Y.Z`; CHANGELOG / release notes written.
- [ ] CI published multi-arch images to GHCR
      (`ghcr.io/laraibkazi92/trellis-agent-platform:vX.Y.Z`).
- [ ] `TRELLIS_IMAGE` default in docker-compose.yml updated to the new tag.
- [ ] Upgrade instructions re-read **from the tag**, not from `main`
      (`git show vX.Y.Z:docs/upgrading.md`) — a doc fix that lands after tagging does not
      reach anyone who checks out the tag.
- [ ] Fresh-clone smoke test: `cp .env.example .env && docker compose up -d`, agent call over
      REST and `/mcp` both succeed, `db-sync` completes.
- [ ] Upgrade smoke test: previous tag → this tag via `docker compose pull && up -d`.

Changes to declare (state "none" where nothing changed):

- Compose services: added / removed / renamed / changed healthchecks, ports, volumes, caps.
- `.env` keys: added (defaulted?), renamed, removed.
- Registry sync (`scripts/sync_to_db.py`): new manifest fields, prune-guard behavior,
  categories scanned.
- Tool protocol / `workspace/` layout: any change is BREAKING — describe the migration.
- Data migrations: etcd storage version, embeddings model/dimensions, volume ownership.
- Image pins: Hindsight server tag vs. `hindsight-client`, etcd minor.
```
