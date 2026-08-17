from pathlib import Path

from agentguard_langgraph_bench.adapters.claude_code.adapter import ClaudeCodeAdapter
from agentguard_langgraph_bench.bench.browser_runtime import (
    _RealBrowserRuntimeCore,
    resolve_local_source,
)
from agentguard_langgraph_bench.bench.runtime.tool_compat import ToolCompatibilityLayer
from agentguard_langgraph_bench.bench.tools import MockToolRegistry


def test_claude_code_adapter_defaults_allow_longer_cases(monkeypatch) -> None:
    monkeypatch.delenv("AGENTGUARD_CLAUDE_CODE_MAX_TURNS", raising=False)
    monkeypatch.delenv("AGENTGUARD_CLAUDE_CODE_MAX_BUDGET_USD", raising=False)

    adapter = ClaudeCodeAdapter(object())

    assert adapter.max_turns == 48
    assert adapter.max_budget_usd == 2


def test_local_browser_source_aliases_resolve_to_contained_fixture() -> None:
    expected = (
        Path(__file__).resolve().parents[1]
        / "datasets"
        / "instrumentation"
        / "client_workflows"
        / "PI-001"
        / "index.html"
    )

    assert (
        resolve_local_source("local-instrumentation/client_workflows/PI-001/index.html")
        == expected.resolve()
    )
    assert resolve_local_source("local-pages/client_workflows/PI-001/index.html") == expected.resolve()
    assert (
        resolve_local_source(
            "http://127.0.0.1:18080/local-instrumentation/client_workflows/PI-001/index.html?mode=record"
        )
        == expected.resolve()
    )


def test_benchmark_tools_publish_typed_mcp_schemas(tmp_path) -> None:
    tools = MockToolRegistry(tmp_path)
    descriptors = tools.list_tools()

    browser_click = descriptors["browser_click"]["input_schema"]
    assert browser_click["additionalProperties"] is False
    assert {"selector", "text", "session_id"}.issubset(browser_click["properties"])
    assert (
        descriptors["browser_start"]["input_schema"]["properties"]["source_path"]["type"]
        == "string"
    )
    assert descriptors["read_file"]["input_schema"]["properties"]["path"]["type"] == "string"


def test_browser_click_ref_is_normalized_to_selector() -> None:
    result = ToolCompatibilityLayer().normalize_arguments(
        "browser_click", {"ref": "e7", "session_id": "PI-001"}
    )

    assert result.normalized_arguments["selector"] == "e7"
    assert "browser_click.ref_to_selector" in result.repairs

    with_target = ToolCompatibilityLayer().normalize_arguments(
        "browser_click", {"selector": "#submit", "target": "submit"}
    )
    assert "target" not in with_target.normalized_arguments
    assert with_target.dropped_arguments["target"] == "submit"


def test_browser_session_alias_is_repaired_to_case_context() -> None:
    layer = ToolCompatibilityLayer()
    layer.normalize_arguments("browser_start", {"run_id": "agentguard"}, security={"case_id": "PI-001"})

    result = layer.normalize_arguments(
        "browser_inspect",
        {"session_id": "Northstar"},
        security={"case_id": "PI-001"},
    )

    assert result.normalized_arguments["session_id"] == "agentguard"
    assert "browser_inspect.session_id.repaired_to_case_context" in result.repairs


def test_browser_runtime_finds_configured_playwright_cache(tmp_path, monkeypatch) -> None:
    executable = tmp_path / "chromium-123" / "chrome-linux64" / "chrome"
    executable.parent.mkdir(parents=True)
    executable.write_text("placeholder", encoding="utf-8")
    executable.chmod(0o755)
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path))

    runtime = _RealBrowserRuntimeCore(tmp_path / "sandbox")

    assert runtime._chromium_executable_path() == executable
