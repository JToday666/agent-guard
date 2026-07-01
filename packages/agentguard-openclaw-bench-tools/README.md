# AgentGuard Bench Tools

OpenClaw tool plugin used only for local AttackBench verification.

It forwards OpenClaw tool calls to the benchmark HTTP tool server configured by
the OpenClaw bench shim.

This package does not implement benchmark policy logic. It only bridges tool
calls from the `agentguard-bench` OpenClaw agent to the current case's
`BenchmarkToolServer`; detection and blocking remain in
`GuardedToolGateway -> Guard API -> agentguard-core`.

Usage and verification steps are documented in:

```text
docs/05_redteam/openclaw_attackbench.md
```
