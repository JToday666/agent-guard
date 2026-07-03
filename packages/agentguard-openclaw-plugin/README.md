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

For local OpenClaw runtime validation, use the repository-level development
installer:

```bash
pnpm openclaw:plugin:install
pnpm openclaw:plugin:verify
```

The complete deployment, install, configuration, verification, uninstall, and
troubleshooting guide is maintained in
[`docs/03_adapters/openclaw_plugin_deployment.md`](../../docs/03_adapters/openclaw_plugin_deployment.md).

`openclaw plugins validate --root ... --entry ...` in OpenClaw 2026.6.6
validates simple tool plugin metadata exposed by `defineToolPlugin`. This
package is a hook-only `definePluginEntry` plugin; if validate reports missing
tool-plugin metadata, runtime validation should use install, inspect, doctor,
gateway status, and hook-trigger tests.

Expected runtime hooks after install:

- P1 enforcement: `before_tool_call`, `message_sending`,
  `before_prompt_build`, `llm_input`
- P1 output/result containment: `llm_output`, `before_agent_finalize`,
  `tool_result_persist`
- P2 config gate: `before_install`
- P2 observation: `gateway_start`, `gateway_stop`, `session_start`,
  `session_end`, `before_compaction`, `after_compaction`, `subagent_spawned`,
  `subagent_ended`, `model_call_started`, `model_call_ended`, `cron_changed`,
  `resolve_exec_env`

`llm_input` and `llm_output` require
`plugins.entries.agentguard-security.hooks.allowConversationAccess=true` in the
OpenClaw config. The repository-level development installer writes this setting.

To remove the development install from the local OpenClaw profile:

```bash
pnpm openclaw:plugin:uninstall
```

Dashboard/API acceptance uses the Dashboard/browser session cookie:

```bash
curl -s "http://127.0.0.1:8088/v1/audit/events?runtime=openclaw"
curl -s "http://127.0.0.1:8088/v1/audit/integrity"
curl -s "http://127.0.0.1:8088/v1/traces/<trace_id>/provenance"
```

Full hook reliability acceptance uses the isolated PostgreSQL test database
from `AGENTGUARD_TEST_DATABASE_URL`:

```bash
pnpm openclaw:plugin:reliability
```

The reliability runner triggers all 19 registered hooks 50 times each, starts a
temporary Guard API pointed at the `_test` database, and writes:

```text
/tmp/agentguard-openclaw-reliability-report.json
/tmp/agentguard-openclaw-reliability-acceptance-report.md
```
