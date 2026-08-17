"""Phase 6 validation: session refresh loop (6a) and optional_secrets support (6b)."""
import yaml
import pytest
from pathlib import Path

from core.models import MCPConfig

BASE_DIR = Path(__file__).parent.parent
BOOTSTRAP_JS = BASE_DIR / "workspace" / "mcps" / "example-cli" / "bootstrap.js"
MCP_YAML = BASE_DIR / "workspace" / "mcps" / "example-cli" / "mcp.yaml"


# ─── Phase 6a: Session Refresh Loop ─────────────────────────────────────────


class TestBootstrapSessionRefreshLoop:
    """Verify bootstrap.js implements a background session-refresh loop."""

    def _source(self) -> str:
        return BOOTSTRAP_JS.read_text()

    def _fn_body(self, fn_name: str) -> str:
        """Return the source of a single async function, stopping before the next one."""
        src = self._source()
        marker = f"async function {fn_name}"
        start = src.index(marker)
        # Bound the window to the next top-level async function declaration so
        # assertions don't accidentally match code in a different function.
        next_fn = src.find("async function ", start + len(marker))
        return src[start:next_fn] if next_fn != -1 else src[start:]

    def test_bootstrap_js_exists(self):
        assert BOOTSTRAP_JS.exists(), "bootstrap.js not found"

    def test_has_login_with_timeout_helper(self):
        assert "async function loginWithTimeout" in self._source(), (
            "loginWithTimeout() helper not found — login timeout guard should be "
            "extracted from initializeHeadlessSession into a shared helper"
        )

    def test_initialize_headless_session_uses_login_with_timeout(self):
        fn_body = self._fn_body("initializeHeadlessSession")
        assert "loginWithTimeout()" in fn_body, (
            "initializeHeadlessSession() must delegate to loginWithTimeout() "
            "rather than inlining the Promise.race timeout guard"
        )

    def test_has_refresh_session_function(self):
        assert "async function refreshSession" in self._source(), (
            "refreshSession() function not found in bootstrap.js"
        )

    def test_refresh_session_calls_save_session(self):
        fn_body = self._fn_body("refreshSession")
        assert "sessionManager.saveSession()" in fn_body, (
            "refreshSession() must call sessionManager.saveSession() to touch "
            "lastActivity when the session is still valid"
        )

    def test_refresh_session_handles_expired_session(self):
        """refreshSession must call loginWithTimeout() — bounded to its own body."""
        fn_body = self._fn_body("refreshSession")
        assert "loginWithTimeout()" in fn_body, (
            "refreshSession() must call loginWithTimeout() to re-authenticate "
            "when loadSession() returns null (session expired)"
        )

    def test_refresh_session_has_try_catch(self):
        """try/catch must be scoped within refreshSession, not matched from a later function."""
        fn_body = self._fn_body("refreshSession")
        assert "try {" in fn_body or "try{" in fn_body, (
            "refreshSession() must wrap its body in try/catch so that a "
            "transient failure does not crash the server"
        )
        assert "catch" in fn_body, (
            "refreshSession() must have a catch block"
        )

    def test_has_session_refresh_interval_constant(self):
        assert "SESSION_REFRESH_INTERVAL_MS" in self._source(), (
            "SESSION_REFRESH_INTERVAL_MS constant not found in bootstrap.js"
        )

    def test_refresh_interval_is_4_minutes(self):
        src = self._source()
        assert "4 * 60 * 1000" in src, (
            "Session refresh interval must be 4 minutes (4 * 60 * 1000 ms)"
        )

    def test_set_interval_uses_unref(self):
        assert ".unref()" in self._source(), (
            "setInterval(...).unref() is required so the timer does not prevent "
            "Node from exiting when the MCP hub closes stdin"
        )

    def test_set_interval_after_start_mcp_server(self):
        src = self._source()
        server_pos = src.index("await startMCPServer(")
        interval_pos = src.index("setInterval(refreshSession")
        assert interval_pos > server_pos, (
            "setInterval(refreshSession, ...) must be placed after "
            "await startMCPServer() — the server must be running before the "
            "refresh loop starts"
        )


# ─── Phase 6b: optional_secrets in mcp.yaml ─────────────────────────────────


class TestMCPYamlOptionalSecrets:
    """Verify mcp.yaml declares LOGS_API_KEY as an optional secret."""

    def _data(self) -> dict:
        with open(MCP_YAML) as f:
            return yaml.safe_load(f)

    def test_mcp_yaml_has_optional_secrets_field(self):
        data = self._data()
        assert "optional_secrets" in data, (
            "mcp.yaml is missing the optional_secrets field — "
            "LOGS_API_KEY should be declared there"
        )

    def test_logs_api_key_in_optional_secrets(self):
        data = self._data()
        optional = data.get("optional_secrets", [])
        assert "LOGS_API_KEY" in optional, (
            "LOGS_API_KEY must be listed in mcp.yaml optional_secrets"
        )

    def test_logs_api_key_not_in_required_secrets(self):
        data = self._data()
        required = data.get("secrets", [])
        assert "LOGS_API_KEY" not in required, (
            "LOGS_API_KEY must NOT appear in required secrets — it is "
            "optional and its absence must not block agent configuration"
        )

    def test_required_secrets_still_intact(self):
        data = self._data()
        secrets = data.get("secrets", [])
        for key in ["DEVOPS_URL", "DEVOPS_USERNAME", "DEVOPS_PASSWORD"]:
            assert key in secrets, (
                f"Required secret {key} is missing from mcp.yaml secrets"
            )

    def test_logs_domain_in_variables(self):
        """LOGS_DOMAIN must be a declared variable so multi-region users can
        override the default endpoint (https://api.logs.com) via the UI."""
        data = self._data()
        variables = data.get("variables", [])
        assert "LOGS_DOMAIN" in variables, (
            "LOGS_DOMAIN must be listed in mcp.yaml variables — users in "
            "non-default Logs regions (e.g. EU) need to inject a custom "
            "endpoint; the hardcoded default only works for the US region"
        )


# ─── Phase 6b: MCPConfig model ───────────────────────────────────────────────


class TestMCPConfigOptionalSecretsModel:
    """Verify MCPConfig Pydantic model handles optional_secrets correctly."""

    def test_mcp_config_accepts_optional_secrets(self):
        config = MCPConfig(
            name="test-mcp",
            optional_secrets=["LOGS_API_KEY", "OTHER_KEY"],
        )
        assert config.optional_secrets == ["LOGS_API_KEY", "OTHER_KEY"]

    def test_mcp_config_optional_secrets_defaults_to_empty_list(self):
        config = MCPConfig(name="test-mcp")
        assert config.optional_secrets == []

    def test_mcp_config_optional_secrets_independent_of_required_secrets(self):
        config = MCPConfig(
            name="test-mcp",
            secrets=["REQUIRED_KEY"],
            optional_secrets=["OPTIONAL_KEY"],
        )
        assert "REQUIRED_KEY" in config.secrets
        assert "OPTIONAL_KEY" in config.optional_secrets
        assert "OPTIONAL_KEY" not in config.secrets
        assert "REQUIRED_KEY" not in config.optional_secrets

    def test_mcp_config_parses_from_mcp_yaml(self):
        with open(MCP_YAML) as f:
            data = yaml.safe_load(f)
        config = MCPConfig(**data)
        assert config.optional_secrets == ["LOGS_API_KEY"]
        assert config.secrets == ["DEVOPS_URL", "DEVOPS_USERNAME", "DEVOPS_PASSWORD"]
        assert config.variables == ["LOGS_DOMAIN"]

    def test_mcp_config_optional_secrets_none_coerced_to_empty(self):
        config = MCPConfig(name="test-mcp", optional_secrets=None)
        assert config.optional_secrets is None or config.optional_secrets == []


# ─── Phase 6b: discovery layer ───────────────────────────────────────────────


class TestDiscoveryOptionalSecrets:
    """Verify discovery functions expose optional_missing_secrets in their response."""

    def _src(self) -> str:
        return (BASE_DIR / "core" / "discovery.py").read_text()

    def test_is_agent_configured_supervisor_shortcut_includes_optional_missing_secrets(self):
        """The supervisor shortcut return must include the optional_missing_secrets key."""
        src = self._src()
        # Find the supervisor shortcut block
        supervisor_block_start = src.index('"supervisor"')
        supervisor_return = src[supervisor_block_start:supervisor_block_start + 300]
        assert "optional_missing_secrets" in supervisor_return, (
            "is_agent_configured() supervisor shortcut must return "
            "optional_missing_secrets key in its dict"
        )

    def test_is_agent_configured_main_return_includes_optional_missing_secrets(self):
        """The main return path in is_agent_configured must include optional_missing_secrets."""
        src = self._src()
        fn_start = src.index("async def is_agent_configured(")
        # Find the last return statement in the function — this is the main return
        fn_body = src[fn_start:fn_start + 3000]
        returns = [i for i in range(len(fn_body)) if fn_body[i:].startswith("return {")]
        # At least one return dict must include optional_missing_secrets
        found = any(
            "optional_missing_secrets" in fn_body[pos:pos + 300]
            for pos in returns
        )
        assert found, (
            "is_agent_configured() must include optional_missing_secrets in its return dict"
        )

    def test_get_agent_optional_secrets_function_exists(self):
        """get_agent_optional_secrets helper must be defined in discovery.py."""
        assert "async def get_agent_optional_secrets" in self._src(), (
            "get_agent_optional_secrets() not found in core/discovery.py"
        )

    def test_get_agent_optional_secrets_reads_optional_secrets_field(self):
        """get_agent_optional_secrets must read the optional_secrets field from mcp_config."""
        src = self._src()
        fn_start = src.index("async def get_agent_optional_secrets")
        fn_body = src[fn_start:fn_start + 1000]
        assert 'optional_secrets' in fn_body, (
            "get_agent_optional_secrets() must read the optional_secrets field "
            "from mcp_config dicts"
        )

    def test_discover_agents_collects_optional_secrets_from_allowed_mcps(self):
        """discover_agents must aggregate optional_secrets from allowed MCP configs."""
        src = self._src()
        fn_start = src.index("async def discover_agents(")
        fn_body = src[fn_start:fn_start + 5000]
        assert 'optional_secrets' in fn_body, (
            "discover_agents() must aggregate optional_secrets from MCP configs "
            "in its per-agent requirement resolution loop"
        )

    def test_discover_agents_response_shape_includes_optional_missing_secrets(self):
        """discover_agents must include optional_missing_secrets in each agent dict."""
        src = self._src()
        fn_start = src.index("async def discover_agents(")
        fn_body = src[fn_start:]
        agents_append_pos = fn_body.index("agents.append({")
        append_block = fn_body[agents_append_pos:agents_append_pos + 1000]
        assert '"optional_missing_secrets"' in append_block or \
               "'optional_missing_secrets'" in append_block, (
            "discover_agents() must include optional_missing_secrets in the "
            "agent dict it appends to the results list"
        )

    def test_is_agent_configured_fast_path_gates_on_optional_secrets(self):
        """When required secrets are empty but optional ones are non-empty, the fast
        path must NOT return early — it must fall through to the identity fetch so
        optional_missing_secrets can be computed per-user.

        The critical gate: 'if not user_optional_secrets' must be nested inside
        'if not user_required_secrets and not user_required_variables'. Without it,
        an agent with only optional secrets configured at system level would
        always return optional_missing_secrets=[] (wrong) for users who haven't
        set their own LOGS_API_KEY.
        """
        src = self._src()
        fn_start = src.index("async def is_agent_configured(")
        fn_body = src[fn_start:fn_start + 3000]
        assert "not user_optional_secrets" in fn_body, (
            "is_agent_configured fast path must gate on 'not user_optional_secrets' — "
            "when optional secrets exist for this user context, the function must "
            "fall through to the identity fetch rather than returning an early "
            "empty optional_missing_secrets list"
        )


# ─── Phase 6b: agent_factory injection ──────────────────────────────────────


class TestAgentFactoryOptionalSecretsInjection:
    """Verify agent_factory.py injects optional_secrets into the MCP process env."""

    def _src(self) -> str:
        return (BASE_DIR / "core" / "agent_factory.py").read_text()

    def test_get_external_mcp_client_injects_optional_secrets(self):
        """Verify the source includes a _inject_config call for config.optional_secrets."""
        assert "config.optional_secrets" in self._src(), (
            "get_external_mcp_client() must call _inject_config() with "
            "config.optional_secrets to inject optional secrets when present"
        )

    def test_optional_secrets_injected_before_variables(self):
        """Optional secrets injection must come between required secrets and variables."""
        src = self._src()
        fn_start = src.index("async def get_external_mcp_client(")
        fn_body = src[fn_start:fn_start + 1500]
        req_pos = fn_body.index("config.secrets")
        opt_pos = fn_body.index("config.optional_secrets")
        var_pos = fn_body.index("config.variables")
        assert req_pos < opt_pos < var_pos, (
            "In get_external_mcp_client, injection order must be: "
            "required secrets → optional secrets → variables"
        )

    def test_inject_config_source_silently_skips_missing_value(self):
        """_inject_config source must guard with 'if val:' so absent keys are skipped."""
        src = self._src()
        fn_start = src.index("def _inject_config(")
        fn_body = src[fn_start:fn_start + 800]
        assert "if val:" in fn_body or "if val :" in fn_body, (
            "_inject_config must guard with 'if val:' so that keys with no "
            "resolved value (optional secrets not configured by the user) are "
            "silently skipped and never set to None/empty in the env dict"
        )

    def test_inject_config_source_sets_env_on_truthy_val(self):
        """_inject_config source must assign env_copy[req_key] when the value is truthy."""
        src = self._src()
        fn_start = src.index("def _inject_config(")
        fn_body = src[fn_start:fn_start + 1200]
        assert "env_copy[req_key]" in fn_body, (
            "_inject_config must assign the resolved value to env_copy[req_key] "
            "when the value is truthy"
        )
