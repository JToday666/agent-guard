# AgentGuard OpenClaw Plugin

P1 OpenClaw security plugin for AgentGuard. It registers `before_tool_call` and
`message_sending` hooks, evaluates them through Guard API, and fails closed when
Guard API is unavailable.

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
```

For local OpenClaw runtime validation, install from a clean staging directory
that contains `dist/`, `openclaw.plugin.json`, `package.json`, and `README.md`.
Do not install directly from the pnpm workspace package directory because its
`node_modules` symlinks are rejected by OpenClaw's local install safety scan.

```bash
openclaw plugins install -l /tmp/agentguard-openclaw-plugin-install-p1
openclaw plugins inspect agentguard-security --runtime --json
openclaw plugins doctor
openclaw gateway restart --safe
openclaw gateway status
```

`openclaw plugins validate --root ... --entry ...` in OpenClaw 2026.6.6
validates simple tool plugin metadata exposed by `defineToolPlugin`. This P1
package is a hook-only `definePluginEntry` plugin, so runtime validation should
use install, inspect, doctor, gateway status, and hook-trigger tests.
