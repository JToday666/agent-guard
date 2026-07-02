from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

for relative in (
    "packages/agentguard-langgraph-adapter",
    "packages/agentguard-core",
    "apps/guard-api",
    "agentguard_langgraph_bench/src",
):
    path = ROOT / relative
    if path.exists():
        sys.path.insert(0, str(path))
