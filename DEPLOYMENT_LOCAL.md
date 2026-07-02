# Local LangGraph and OpenClaw Deployment

This repo is deployed under `/home/zhuwei/code` with local, repo-scoped tools.

## Paths

- Python virtualenv: `/home/zhuwei/code/agent-guard/.venv`
- Node 24.15.0: `/home/zhuwei/code/.tools/node-v24.15.0-linux-x64`
- pnpm 11.5.2 wrapper: `/home/zhuwei/code/.tools/bin/pnpm`
- OpenClaw wrapper: `/home/zhuwei/code/.tools/bin/openclaw`
- OpenClaw state/config: `/home/zhuwei/code/.openclaw`
- AgentGuard OpenClaw plugin staging: `/home/zhuwei/code/agent-guard/.openclaw-dev/agentguard-security`

## Use The Environment

From `/home/zhuwei/code/agent-guard`:

```bash
. scripts/use-local-deps.sh
```

After sourcing, these should work:

```bash
python -c "import langgraph; print('langgraph ok')"
node --version
pnpm --version
openclaw --version
openclaw config file
```

## Verified Versions

- Python: local `.venv` on Python 3.13
- LangGraph: `1.2.6`
- LangChain Core: `1.4.8`
- OpenClaw: `2026.6.6`
- Node: `24.15.0`
- pnpm: `11.5.2`

## Verification Commands

```bash
. scripts/use-local-deps.sh

python scripts/langgraph_smoke.py
python -m pytest tests/test_openclaw_plugin_contract.py -q
python -m pytest agentguard_langgraph_bench/bench/tests/test_langgraph_adapter.py agentguard_langgraph_bench/bench/tests/test_core_client.py -q
pnpm --filter @agentguard/openclaw-plugin test
openclaw plugins inspect agentguard-security --runtime --json
openclaw security audit
```

Expected highlights:

- LangGraph smoke output: `{'value': 'langgraph ok'}`
- OpenClaw plugin: `status=loaded`, `hookCount=16`
- OpenClaw security audit: `0 critical`, `0 warn`

## OpenClaw Gateway Note

The OpenClaw CLI and plugin are installed and verified. The gateway foreground
startup reaches plugin loading, but this WSL/sandbox environment resolves local
binds to `0.0.0.0`, so OpenClaw refuses to continue:

```text
gateway bind=custom requested 127.0.0.1 but resolved 0.0.0.0; refusing fallback
```

The stability bundle confirms `plugins.load` completed before that bind safety
check failed. On a normal host, or after fixing WSL/systemd/network interface
reporting, run:

```bash
. scripts/use-local-deps.sh
openclaw gateway run --allow-unconfigured --port 18789 --bind custom --token local-openclaw-dev-token
```

The code-local OpenClaw config is `/home/zhuwei/code/.openclaw/openclaw.json`.
