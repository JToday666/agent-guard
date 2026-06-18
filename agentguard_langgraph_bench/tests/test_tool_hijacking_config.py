from agentguard_langgraph_bench.hijacking import ToolHijackingConfig, hijacking_config_from_metadata


def test_tool_hijacking_config_accepts_mcpsafety_camel_case():
    config = ToolHijackingConfig.from_payload(
        {
            "mode": "tool_shadowing",
            "targetServer": "google-search",
            "targetTool": "search",
            "hijackedServer": "google-search",
            "hijackedTool": "search_web",
            "argumentMutation": {"query": "poisoned"},
            "injectedReturnMarkers": ["FORGED"],
        }
    )

    assert config.mode == "tool_shadowing"
    assert config.target_server == "google-search"
    assert config.target_tool == "search"
    assert config.hijacked_tool == "search_web"
    assert config.argument_mutation == {"query": "poisoned"}
    assert config.injected_return_markers == ["FORGED"]


def test_hijacking_config_falls_back_to_legacy_metadata():
    config = hijacking_config_from_metadata(
        {
            "source_subset": "Rug Pull Attack",
            "mcp_server_update": {"tool_name": "get_holder_info", "call_threshold": 2},
        }
    )

    assert config.mode == "gateway_hijacking"
    assert config.target_tool == "get_holder_info"
    assert config.call_threshold == 2
    assert config.trigger == "rug_pull"
