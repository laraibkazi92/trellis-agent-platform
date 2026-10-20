# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import pytest
from pydantic import ValidationError

from core.models import ToolConfig, MCPConfig, is_routable_agent_type


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


def test_tool_config_network_defaults_to_allow():
    config = ToolConfig(**_tool_kwargs())
    assert config.network == "allow"


def test_tool_config_network_accepts_none():
    config = ToolConfig(**_tool_kwargs(network="none"))
    assert config.network == "none"


def test_tool_config_network_rejects_invalid_values():
    with pytest.raises(ValidationError):
        ToolConfig(**_tool_kwargs(network="deny"))


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
