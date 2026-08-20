from core.models import ToolConfig, MCPConfig


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
