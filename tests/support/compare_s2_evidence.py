"""Compare redacted Memory/PostgreSQL S2 evidence artifacts in CI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _load_one(root: Path, backend: str) -> dict[str, Any]:
    matches = list(root.rglob("s2-evidence.json"))
    if len(matches) != 1:
        raise AssertionError(f"expected one {backend} artifact, found {matches}")
    payload = json.loads(matches[0].read_text(encoding="utf-8"))
    if payload.get("storage_backend") != backend:
        raise AssertionError(f"{backend} artifact reports {payload.get('storage_backend')}")
    return payload


def _semantic(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "case_id": payload["case_id"],
        "conditional_reads": payload["conditional_reads"],
        "event_types": payload["event_types"],
        "full_envelope_event_types": payload["full_envelope_event_types"],
        "missing_event_types": payload["missing_event_types"],
        "missing_full_envelopes": payload["missing_full_envelopes"],
        "readiness": payload["readiness"],
        "runtime_profile": payload["runtime_profile"],
        "typed_edge_count": len(payload["typed_edge_ids"]),
        "typed_node_count": len(payload["typed_node_ids"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--memory", type=Path, required=True)
    parser.add_argument("--postgres", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    memory = _semantic(_load_one(args.memory, "memory"))
    postgres = _semantic(_load_one(args.postgres, "postgres"))
    if memory != postgres:
        raise AssertionError(
            json.dumps({"memory": memory, "postgres": postgres}, indent=2, sort_keys=True)
        )
    result = {"schema": "agentguard-s2-parity/1.0", "status": "passed", **memory}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
