"""Evaluate one or more repository-local GuardEvent JSON examples."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from agentguard_core import GuardEvent, evaluate


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: evaluate_events.py EVENT.json [EVENT.json ...]", file=sys.stderr)
        return 2

    for raw_path in argv:
        path = Path(raw_path)
        event = GuardEvent.model_validate_json(path.read_text(encoding="utf-8"))
        decision = evaluate(event)
        print(
            json.dumps(
                {
                    "decision": decision.decision,
                    "event_id": event.event_id,
                    "risk_score": decision.risk_score,
                    "rule_hits": [hit.rule_id for hit in decision.rule_hits],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
