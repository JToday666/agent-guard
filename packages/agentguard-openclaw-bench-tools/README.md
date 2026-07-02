# Local Task Tools

OpenClaw tool plugin used for local task execution.

It forwards OpenClaw tool calls to the local HTTP tool server configured by the
OpenClaw task shim.

This package does not implement policy logic. It only bridges tool calls from
the `local-task-runner` OpenClaw agent to the current local tool server;
detection and blocking remain in the guarded gateway path.

Usage and verification steps are documented in:

```text
docs/05_redteam/openclaw_attackbench.md
```
