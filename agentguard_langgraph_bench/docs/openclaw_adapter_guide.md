# OpenClaw Adapter Guide

The OpenClaw adapter is a normal pluggable adapter under:

```text
agentguard_langgraph_bench/adapters/openclaw/
```

It is not hardcoded in `bench/runner.py`; runner loads it through `bench/runtime/adapter_loader.py`.

## Run Shape

```bash
python -m agentguard_langgraph_bench.bench.cli \
  --agent-adapter openclaw \
  --adapter-config agentguard_langgraph_bench/adapters/openclaw/config.example.toml \
  --tool-server-mode http \
  --dataset agentguard_langgraph_bench/bench/datasets/attack_cases/tool_hijacking.jsonl \
  --defense off
```

The expected chain is:

```text
bench runner
-> OpenClawAdapter
-> external/fake OpenClaw runtime
-> benchmark HTTP Tool Server
-> GuardedToolGateway
-> SandboxToolRuntime
-> CaseRunResult
-> bench scoring
```

## Tool Manifest

`tool_manifest.py` builds a manifest from `ToolRuntime.list_tools()` and adds HTTP endpoints:

```json
{
  "tools": [
    {
      "name": "read_file",
      "description": "Read a file from the benchmark sandbox.",
      "input_schema": {"type": "object"},
      "endpoint": "http://127.0.0.1:18090/tools/read_file"
    }
  ]
}
```

OpenClaw or fake OpenClaw agents must call tool endpoints rather than touching sandbox files directly.

## Oracle Safety

The adapter must not pass scoring answers or policy expectations to OpenClaw. `config.example.toml` keeps `include_oracle = false` by default.
