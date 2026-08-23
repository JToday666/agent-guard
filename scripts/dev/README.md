# Development scripts

Canonical home for local setup, smoke, adapter, and plugin-development automation.

Compatibility entry points currently retained at `scripts/`:

- `dashboard-check-changed.sh`
- `guard-api-endpoint.mjs`
- `openclaw-*-dev.mjs`
- `openclaw-command-resolve.mjs`
- `openclaw-e2e-runner.mjs`
- `openclaw-runtime-smoke.mjs`
- `claude_code_smoke.py`

Move an entry point here only together with wrapper, import-path, package-script, documentation, and CI coverage.
