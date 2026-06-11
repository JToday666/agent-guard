from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

for relative in (
    "packages/agentguard-core",
    "apps/guard-api",
    "agentguard_langgraph_bench/src",
):
    path = ROOT / relative
    if path.exists():
        sys.path.insert(0, str(path))
