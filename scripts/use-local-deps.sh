#!/usr/bin/env sh
# Source this file from the agent-guard repo root:
#   . scripts/use-local-deps.sh

SCRIPT_PATH="${BASH_SOURCE:-$0}"
ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$SCRIPT_PATH")/../.." && pwd)"
AGENT_GUARD_DIR="$ROOT_DIR/agent-guard"

export PATH="$ROOT_DIR/.tools/bin:$ROOT_DIR/.tools/node-v24.15.0-linux-x64/bin:$AGENT_GUARD_DIR/node_modules/.pnpm/node_modules/.bin:$AGENT_GUARD_DIR/packages/agentguard-openclaw-plugin/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export COREPACK_HOME="$ROOT_DIR/.cache/corepack"
export npm_config_cache="$ROOT_DIR/.cache/npm"
export PIP_CACHE_DIR="$ROOT_DIR/.cache/pip"
export PNPM_HOME="$ROOT_DIR/.tools/bin"
export VIRTUAL_ENV="$AGENT_GUARD_DIR/.venv"
export OPENCLAW_HOME="$ROOT_DIR/.openclaw-home"
export OPENCLAW_STATE_DIR="$ROOT_DIR/.openclaw"
export OPENCLAW_CONFIG_PATH="$ROOT_DIR/.openclaw/openclaw.json"

if [ -d "$VIRTUAL_ENV/bin" ]; then
  export PATH="$VIRTUAL_ENV/bin:$PATH"
fi
