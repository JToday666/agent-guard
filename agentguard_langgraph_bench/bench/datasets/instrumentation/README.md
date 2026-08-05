# Instrumentation local environments

This directory contains local copies of the Instrumentation HTML task
environments used by AttackBench cases.

The copied directories are read-only fixtures for the benchmark runtime. They
come from `../../../../Instrumentation/` and are copied here so the benchmark can
serve them through the local `browser_start` runtime without depending on
external network access.

Covered malicious case groups:

- `prompt_injection.jsonl`: 10 EIA/VPI/BrowserART A, B, and C cases.
- `file_exfiltration.jsonl`: 5 Instrumentation-derived file exfiltration cases.
- `agent_abuse.jsonl`: 10 BrowserART D, E, F, and G cases.

The complete case-to-environment mapping is recorded in
`../environment_manifest.json`.
