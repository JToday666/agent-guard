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
export UV_CACHE_DIR="${UV_CACHE_DIR:-${repo_root}/.uv-cache}"

echo "[alpha] checking whitespace and Markdown targets"
alpha_base_ref="${ALPHA_BASE_REF:-origin/dev}"
if git rev-parse --verify --quiet "${alpha_base_ref}^{commit}" >/dev/null; then
  git diff --check "${alpha_base_ref}...HEAD"
elif git rev-parse --verify --quiet "HEAD^{commit}" >/dev/null; then
  git diff-tree --check --no-commit-id -r HEAD
else
  echo "unable to resolve a Git revision for committed diff checks" >&2
  exit 2
fi
git diff --check
uv run python scripts/release/check_markdown_links.py

echo "[alpha] checking Python"
uv run ruff check apps packages scripts tests examples conftest.py \
  agentguard_langgraph_bench/bench/tests/conftest.py
pnpm python:format:check
pnpm python:typecheck
uv run pytest -q -m "unit or contract or integration"

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
uv run pytest -q -m e2e
pnpm --filter @agentguard/dashboard test:e2e
pnpm --filter @agentguard/dashboard test:e2e:api
uv run --frozen python scripts/release/productization_alpha_acceptance.py \
  --postgresql-url "${AGENTGUARD_TEST_DATABASE_URL}" --json

echo "[alpha] building local artifacts without publishing"
python_package_specs=(
  "apps/cli:aegis-agentguard-cli"
  "apps/guard-api:aegis-agentguard-api"
  "packages/agentguard-core:aegis-agentguard-core"
  "packages/agentguard-langgraph-adapter:agentguard-langgraph-adapter"
  "agentguard_langgraph_bench/bench:agentguard-langgraph-bench"
)
for package_spec in "${python_package_specs[@]}"; do
  IFS=: read -r package_dir artifact_dir <<<"${package_spec}"
  uv build "${package_dir}" --out-dir "release-dist/${artifact_dir}" --no-create-gitignore
done
pnpm --filter @agentguard/dashboard build
pnpm --filter @agentguard-ai/openclaw-plugin build
docker build --file apps/guard-api/Dockerfile \
  --tag agentguard-guard-api:productization-alpha-local .

if ! command -v syft >/dev/null 2>&1; then
  echo "syft is required for --full SBOM generation" >&2
  exit 2
fi
mkdir -p release-dist/sbom
syft dir:. -o cyclonedx-json=release-dist/sbom/agentguard-source.cdx.json
syft agentguard-guard-api:productization-alpha-local -o cyclonedx-json=release-dist/sbom/guard-api-image.cdx.json

echo "[alpha] full gate passed; artifacts remain local under release-dist/"
