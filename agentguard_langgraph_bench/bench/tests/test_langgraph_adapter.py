from agentguard_langgraph_bench.adapter import LangGraphAdapter, create_guarded_tool_node
from agentguard_langgraph_bench.bench.config import BenchConfig, ensure_sandbox
from agentguard_langgraph_bench.bench.tools import MockToolRegistry


def test_create_guarded_tool_node_blocks_with_fake_core(tmp_path):
    ensure_sandbox(tmp_path)
    adapter = LangGraphAdapter.with_fake_deny_core(BenchConfig(defense_enabled=True, sandbox_dir=tmp_path))
    node = create_guarded_tool_node(adapter, MockToolRegistry(tmp_path))

    output = node(
        {
            "trace_id": "trace_node",
            "security": {
                "case_id": "PI-001",
                "attack_type": "prompt_injection",
                "is_malicious": True,
            },
            "tool_calls": [
                {"id": "call_1", "name": "write_file", "args": {"path": "/reports/no.txt", "content": "no"}}
            ],
        }
    )

    assert output["tool_results"][0]["blocked"] is True
    assert not (tmp_path / "files" / "reports" / "no.txt").exists()
