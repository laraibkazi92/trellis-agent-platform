# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import logging
import threading
import time

import pytest
from pydantic import ValidationError

from core.models import (
    MCPConfig,
    ToolConfig,
    is_routable_agent_type,
    reset_network_policy_warnings,
)


def _tool_kwargs(**overrides):
    kwargs = dict(
        name="opsctl",
        description="Acme Operations CLI",
        runtime="python",
        entrypoint="wrapper.py",
    )
    kwargs.update(overrides)
    return kwargs


def test_tool_config_public_defaults_false():
    config = ToolConfig(**_tool_kwargs())
    assert config.public is False


def test_tool_config_public_true():
    config = ToolConfig(**_tool_kwargs(public=True))
    assert config.public is True


def test_tool_config_retry_and_timeout_defaults():
    config = ToolConfig(**_tool_kwargs())
    assert config.retry_on_transient is True
    assert config.timeout_seconds is None


def test_tool_config_network_defaults_to_egress():
    """v0.7.1 flips the default: an undeclared tool gets ordinary Docker egress."""
    config = ToolConfig(**_tool_kwargs())
    assert config.network == "egress"


@pytest.mark.parametrize("legacy", ["allow", "internet", "internal"])
def test_legacy_network_values_normalize_to_egress(caplog, legacy):
    """The v0.6 profiles all meant "may use the network" -- now plain egress."""
    reset_network_policy_warnings()
    with caplog.at_level(logging.WARNING, logger="core.models"):
        config = ToolConfig(**_tool_kwargs(network=legacy))

    assert config.network == "egress"
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert legacy in warnings[0]
    assert "egress" in warnings[0]


def test_legacy_network_warning_is_logged_once_per_value(caplog):
    reset_network_policy_warnings()
    with caplog.at_level(logging.WARNING, logger="core.models"):
        for _ in range(3):
            assert ToolConfig(**_tool_kwargs(network="internal")).network == "egress"

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1


def test_one_deprecation_warning_across_many_manifests(caplog):
    """A whole workspace of legacy values must not flood the log: one line per value."""
    reset_network_policy_warnings()
    with caplog.at_level(logging.WARNING, logger="core.models"):
        for index in range(5):
            config = ToolConfig(**_tool_kwargs(name=f"tool{index}", network="internal"))
            assert config.network == "egress"
        assert MCPConfig(name="legacy-mcp", network="internal").network == "egress"

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "internal" in warnings[0].getMessage()


def test_concurrent_normalization_still_warns_once(caplog, monkeypatch):
    """Warn-once is check-and-add under a lock, not a bare set membership test.

    Manifests are normalized from several threads at startup (registry sync, a hub
    warm-up, an edge reloading its catalog). Without the lock two threads can both
    see the value as new and log it twice, which is what the operator asked not to
    happen. A slow ``add`` makes that window deterministic: the unlocked version
    parks every thread inside it and logs once per thread.
    """
    import core.models as models_module

    class SlowAddSet(set):
        def add(self, value):
            time.sleep(0.02)
            super().add(value)

    monkeypatch.setattr(models_module, "_WARNED_NETWORK_POLICIES", SlowAddSet())
    reset_network_policy_warnings()

    threads_per_round = 6
    barrier = threading.Barrier(threads_per_round)
    results = []
    errors = []

    def normalize():
        try:
            barrier.wait(timeout=10)
            results.append(ToolConfig(**_tool_kwargs(network="internal")).network)
        except BaseException as exc:  # surfaced below, not swallowed
            errors.append(exc)

    with caplog.at_level(logging.WARNING, logger="core.models"):
        workers = [threading.Thread(target=normalize) for _ in range(threads_per_round)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=10)

    assert not errors, errors
    assert results == ["egress"] * threads_per_round
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1


@pytest.mark.parametrize("legacy", ["deny", "off"])
def test_legacy_deny_values_still_mean_no_network(caplog, legacy):
    reset_network_policy_warnings()
    with caplog.at_level(logging.WARNING, logger="core.models"):
        config = ToolConfig(**_tool_kwargs(network=legacy))

    assert config.network == "none"
    assert [r for r in caplog.records if r.levelno == logging.WARNING] == []


def test_tool_config_network_accepts_none():
    config = ToolConfig(**_tool_kwargs(network="none"))
    assert config.network == "none"


def test_tool_config_network_normalizes_case_and_whitespace():
    assert ToolConfig(**_tool_kwargs(network="  NONE ")).network == "none"
    assert ToolConfig(**_tool_kwargs(network="  EGRESS ")).network == "egress"


def test_tool_config_network_typo_keeps_the_tool(caplog):
    """A typo must not raise: load_tool_configs drops any config that fails."""
    reset_network_policy_warnings()
    with caplog.at_level(logging.WARNING, logger="core.models"):
        config = ToolConfig(**_tool_kwargs(network="denny"))

    assert config.network == "none"
    assert config.name == "opsctl"
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any("denny" in message and "none" in message for message in warnings)


def test_tool_config_egress_defaults_to_empty():
    config = ToolConfig(**_tool_kwargs())
    assert config.egress == []


def test_tool_config_egress_accepts_a_list():
    config = ToolConfig(**_tool_kwargs(egress=["api.example.com", "*.vendor.test"]))
    assert config.egress == ["api.example.com", "*.vendor.test"]


def test_mcp_config_public_defaults():
    config = MCPConfig(name="example-mcp")
    assert config.public is False
    assert config.public_tools == []


def test_mcp_config_public_tools_whitelist():
    config = MCPConfig(name="example-mcp", public=False, public_tools=["clusters_get_all", "accounts_get_all"])
    assert config.public is False
    assert config.public_tools == ["clusters_get_all", "accounts_get_all"]


def test_mcp_config_public_true():
    config = MCPConfig(name="example-mcp", public=True)
    assert config.public is True
    assert config.public_tools == []


# --- is_routable_agent_type (Phase A: shared structural exclusion predicate) ---

def test_is_routable_agent_type_excludes_supervisor():
    assert is_routable_agent_type("supervisor", {"type": "user_agent"}) is False


def test_is_routable_agent_type_excludes_background_agent():
    assert is_routable_agent_type("nightly-sync", {"type": "background_agent"}) is False


def test_is_routable_agent_type_excludes_background_script():
    assert is_routable_agent_type("cleanup-job", {"type": "background_script"}) is False


def test_is_routable_agent_type_true_for_ordinary_user_agent():
    assert is_routable_agent_type("troubleshooting-agent", {"type": "user_agent"}) is True


def test_is_routable_agent_type_fails_open_on_missing_or_none_cfg():
    assert is_routable_agent_type("some-agent", {}) is True
    assert is_routable_agent_type("some-agent", None) is True


def test_is_agent_external_coerces_string_booleans():
    from core.models import is_agent_external, is_agent_internal

    # Genuine booleans
    assert is_agent_external({"external": True}) is True
    assert is_agent_external({"external": False}) is False

    # String booleans (YAML/legacy form inputs)
    assert is_agent_external({"external": "false"}) is False
    assert is_agent_external({"external": "False"}) is False
    assert is_agent_external({"external": "no"}) is False
    assert is_agent_external({"external": "0"}) is False
    assert is_agent_external({"external": "true"}) is True
    assert is_agent_external({"external": "yes"}) is True

    # Defaults and None
    assert is_agent_external({}) is True
    assert is_agent_external(None) is True

    # Internal checks
    assert is_agent_internal({"internal": "false"}) is False
    assert is_agent_internal({"internal": False}) is False
    assert is_agent_internal({"internal": True}) is True
    assert is_agent_internal({}) is True


# --- declared env names -----------------------------------------------------------
# A declared secret/variable name is only usable if a process can carry it as an
# environment variable. `my-api-key` used to be accepted here, then dropped at the
# last mile, so the tool silently ran without it.


@pytest.mark.parametrize("field", ["secrets", "optional_secrets", "variables"])
def test_tool_config_rejects_a_declared_name_that_is_not_an_env_name(field):
    with pytest.raises(ValidationError) as excinfo:
        ToolConfig(**_tool_kwargs(**{field: ["my-api-key"]}))

    message = str(excinfo.value)
    assert "my-api-key" in message
    assert field in message


@pytest.mark.parametrize("field", ["secrets", "variables"])
def test_mcp_config_rejects_a_declared_name_that_is_not_an_env_name(field):
    with pytest.raises(ValidationError) as excinfo:
        MCPConfig(name="demo", command="srv", **{field: ["9bad", "ok_NAME"]})

    assert "9bad" in str(excinfo.value)


def test_the_grouped_declaration_form_is_validated_too():
    with pytest.raises(ValidationError) as excinfo:
        ToolConfig(**_tool_kwargs(secrets={"general": ["GOOD_ONE"], "user": ["my-token"]}))

    assert "my-token" in str(excinfo.value)


def test_valid_declared_names_still_load_in_both_forms():
    config = ToolConfig(
        **_tool_kwargs(
            secrets={"general": ["SHARED_TOKEN"], "user": ["USER_TOKEN"]},
            optional_secrets=["_UNDERSCORE_OK"],
            variables=["SERVICE_URL", "lower_case_ok"],
        )
    )
    assert config.variables == ["SERVICE_URL", "lower_case_ok"]


def test_mcp_config_accepts_valid_declared_names():
    config = MCPConfig(name="demo", command="srv", secrets=["API_KEY"], variables=["BASE_URL"])
    assert config.secrets == ["API_KEY"]


# A `secret_groups` field key is a credential name the user types into /configuration
# and the tool receives as an env var, so it follows exactly the same rule.


def _secret_group(key):
    return [
        {
            "label": "Environment",
            "options": [{"value": "prod", "fields": [{"key": key, "label": "API key"}]}],
        }
    ]


def test_tool_config_rejects_a_secret_group_key_that_is_not_an_env_name():
    with pytest.raises(ValidationError) as excinfo:
        ToolConfig(**_tool_kwargs(secret_groups=_secret_group("my-api-key")))

    message = str(excinfo.value)
    assert "secret_groups" in message
    assert "my-api-key" in message


def test_valid_secret_group_keys_still_load():
    config = ToolConfig(**_tool_kwargs(secret_groups=_secret_group("PROD_API_KEY")))

    assert config.secret_groups[0]["options"][0]["fields"][0]["key"] == "PROD_API_KEY"
