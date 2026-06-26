# AgentGuard OpenClaw Plugin

OpenClaw security plugin for AgentGuard. It registers P1 enforcement hooks
(`before_tool_call`, `message_sending`) plus P2 config/provenance observation
hooks. Enforcement hooks call Guard API and fail closed when Guard API is
unavailable; observation hooks write audit/provenance evidence and fail open.

## Config

```json
{
  "guardApiBaseUrl": "http://127.0.0.1:8088",
  "adapterToken": "<AGENTGUARD_ADAPTER_TOKEN>",
  "requestTimeoutMs": 5000,
  "approvalPollIntervalMs": 1000,
  "approvalTimeoutMs": 120000
}
```

`adapterToken` can also be provided through `AGENTGUARD_ADAPTER_TOKEN`.

## Validation

```bash
pnpm --filter @agentguard/openclaw-plugin build
pnpm --filter @agentguard/openclaw-plugin test
uv run pytest tests/test_openclaw_plugin_contract.py -q
```

For local OpenClaw runtime validation, install from a clean staging directory
that contains `dist/`, `openclaw.plugin.json`, `package.json`, and `README.md`.
Do not install directly from the pnpm workspace package directory because its
`node_modules` symlinks are rejected by OpenClaw's local install safety scan.

```bash
openclaw plugins validate --root packages/agentguard-openclaw-plugin --entry dist/index.js
openclaw plugins install -l /tmp/agentguard-openclaw-plugin-install-p2
openclaw plugins inspect agentguard-security --runtime --json
openclaw plugins doctor
openclaw gateway restart --safe
openclaw gateway status
```

`openclaw plugins validate --root ... --entry ...` in OpenClaw 2026.6.6
validates simple tool plugin metadata exposed by `defineToolPlugin`. This
package is a hook-only `definePluginEntry` plugin; if validate reports missing
tool-plugin metadata, runtime validation should use install, inspect, doctor,
gateway status, and hook-trigger tests.

Expected runtime hooks after install:

- P1 enforcement: `before_tool_call`, `message_sending`
- P2 config gate: `before_install`
- P2 evaluation/observation: `tool_result_persist`, `gateway_start`,
  `gateway_stop`, `session_start`, `session_end`, `before_compaction`,
  `after_compaction`, `subagent_spawned`, `subagent_ended`,
  `model_call_started`, `model_call_ended`, `cron_changed`,
  `resolve_exec_env`

Dashboard/API acceptance uses the Dashboard/browser session cookie:

```bash
curl -s "http://127.0.0.1:8088/v1/audit/events?runtime=openclaw"
curl -s "http://127.0.0.1:8088/v1/audit/integrity"
curl -s "http://127.0.0.1:8088/v1/traces/<trace_id>/provenance"
```
