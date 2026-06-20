"""Evidence collector for agent_abuse browser and sandbox runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .jsonl import read_jsonl


@dataclass(slots=True)
class AgentAbuseEvidence:
    sandbox_dir: Path | None
    browser_events: list[dict[str, Any]] = field(default_factory=list)
    sandbox_events: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    files: dict[str, str] = field(default_factory=dict)
    recordings: list[dict[str, Any]] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)

    def events_for_stream(self, stream: str) -> list[dict[str, Any]]:
        normalized = stream.strip("/")
        values = list(self.sandbox_events.get(normalized, []))
        if normalized.startswith("sandbox/"):
            values.extend(self.sandbox_events.get(normalized.removeprefix("sandbox/"), []))
        return values


def collect_agent_abuse_evidence(row: dict[str, Any], sandbox_dir: Path | None = None) -> AgentAbuseEvidence:
    evidence = AgentAbuseEvidence(sandbox_dir=sandbox_dir, recordings=list(row.get("browser_recordings") or []))
    _load_browser_events(row, evidence)
    if sandbox_dir is not None:
        _load_sandbox_streams(sandbox_dir, evidence)
    _load_side_effect_files(row, evidence)
    return evidence


def _load_browser_events(row: dict[str, Any], evidence: AgentAbuseEvidence) -> None:
    for recording in row.get("browser_recordings") or []:
        if not isinstance(recording, dict):
            continue
        events_path = recording.get("events")
        if not events_path:
            evidence.missing.append("browser_events")
            continue
        path = Path(str(events_path))
        rows = read_jsonl(path)
        if not rows:
            evidence.missing.append(str(path))
        evidence.browser_events.extend(rows)


def _load_sandbox_streams(sandbox_dir: Path, evidence: AgentAbuseEvidence) -> None:
    candidates = [
        sandbox_dir / "api",
        sandbox_dir / "outbox",
        sandbox_dir / "identity",
        sandbox_dir / "social",
        sandbox_dir / "web_state",
    ]
    for root in candidates:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.jsonl")):
            relative = path.relative_to(sandbox_dir).as_posix()
            evidence.sandbox_events[relative] = read_jsonl(path)


def _load_side_effect_files(row: dict[str, Any], evidence: AgentAbuseEvidence) -> None:
    for item in row.get("side_effects") or []:
        if not isinstance(item, dict) or not item.get("path"):
            continue
        path = Path(str(item["path"]))
        if not path.exists() or not path.is_file():
            evidence.missing.append(str(path))
            continue
        try:
            evidence.files[str(path)] = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            evidence.missing.append(str(path))
