#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
mode="${1:-fast}"

if [[ "${mode}" != "fast" && "${mode}" != "--full" ]]; then
  echo "usage: $0 [fast|--full]" >&2
  exit 2
fi

cd "${repo_root}"

echo "[alpha] checking whitespace and generated roadmap contracts"
git diff --check
uv run python scripts/roadmap-tools.py check

echo "[alpha] checking Python"
pnpm python:check
shopt -s nullglob
python_test_paths=(tests apps/*/tests packages/*/tests)
uv run pytest -q -m "not postgres and not e2e and not live" "${python_test_paths[@]}"

echo "[alpha] checking Node workspaces"
pnpm --filter @agentguard/dashboard check
pnpm --filter @agentguard-ai/openclaw-plugin test
pnpm --filter @agentguard/openclaw-bench-tools test
pnpm openclaw:bench-shim:test

if [[ "${mode}" == "fast" ]]; then
  echo "[alpha] fast gate passed"
  exit 0
fi

if [[ -z "${AGENTGUARD_TEST_DATABASE_URL:-}" ]]; then
  echo "AGENTGUARD_TEST_DATABASE_URL is required for --full" >&2
  exit 2
fi

echo "[alpha] running PostgreSQL and browser gates"
uv run pytest -q -m postgres
pnpm --filter @agentguard/dashboard test:e2e

echo "[alpha] building local artifacts without publishing"
uv build --all-packages --out-dir release-dist
pnpm --filter @agentguard/dashboard build
pnpm --filter @agentguard-ai/openclaw-plugin build
docker build --tag agentguard-guard-api:productization-alpha-local apps/guard-api

if ! command -v syft >/dev/null 2>&1; then
  echo "syft is required for --full SBOM generation" >&2
  exit 2
fi
mkdir -p release-dist/sbom
syft dir:. -o cyclonedx-json=release-dist/sbom/agentguard-source.cdx.json
syft agentguard-guard-api:productization-alpha-local -o cyclonedx-json=release-dist/sbom/guard-api-image.cdx.json

echo "[alpha] full gate passed; artifacts remain local under release-dist/"
