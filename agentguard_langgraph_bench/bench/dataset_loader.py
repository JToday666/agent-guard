"""Load AttackCase JSONL files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .models import AttackCase


def iter_jsonl(path: Path) -> Iterable[dict]:
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                yield json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON at {path}:{line_number}: {exc}") from exc


def load_attack_cases(dataset_path: str | Path) -> list[AttackCase]:
    path = Path(dataset_path)
    files = sorted(path.glob("*.jsonl")) if path.is_dir() else [path]
    cases: list[AttackCase] = []
    for file_path in files:
        for payload in iter_jsonl(file_path):
            cases.append(AttackCase.model_validate(payload))
    return cases
