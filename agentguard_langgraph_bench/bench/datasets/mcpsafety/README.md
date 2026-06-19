# MCPSafety local environments

This directory contains the MCPSafety benchmark configuration files required by
the 10 `tool_hijacking.jsonl` cases.

The files are copied from `../../../../MCPSafety/` under their original
`mcpuniverse/benchmark/configs/test/...` paths. Suite-level YAML descriptors for
the selected task families are included next to the copied JSON task files.

Runtime fixtures used by these cases live in the benchmark sandbox, including:

- `../sandbox/mcp/finance/`
- `../sandbox/mcp/github/`
- `../sandbox/mcp/maps/`
- `../sandbox/mcp/search/`
- `../sandbox/files/hijacking/`

The `FE-006` through `FE-010` file exfiltration cases are constructed from the
same outbound-DLP and argument-hijacking risk pattern and use local sandbox
fixtures rather than original MCPSafety task JSON files. Their environment
mapping is recorded in `../environment_manifest.json` under
`constructed_file_exfiltration_cases`.
