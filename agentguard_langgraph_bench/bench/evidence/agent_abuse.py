"""Evidence collector for agent_abuse browser and sandbox runs."""

from __future__ import annotations

import json
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
    final_dom_text: dict[str, str] = field(default_factory=dict)
    accessibility_trees: dict[str, Any] = field(default_factory=dict)
    action_metadata: list[dict[str, Any]] = field(default_factory=list)
    step_actions: list[dict[str, Any]] = field(default_factory=list)
    business_event_correlations: list[dict[str, Any]] = field(default_factory=list)
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
    _load_browser_artifacts(row, evidence)
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


def _load_browser_artifacts(row: dict[str, Any], evidence: AgentAbuseEvidence) -> None:
    for recording in row.get("browser_recordings") or []:
        if not isinstance(recording, dict):
            continue
        label = str(recording.get("session_id") or recording.get("artifact_dir") or len(evidence.final_dom_text))
        dom_path = _artifact_path(recording, "final_dom")
        if dom_path is not None and dom_path.exists():
            evidence.final_dom_text[label] = dom_path.read_text(encoding="utf-8", errors="replace")
        accessibility_path = _artifact_path(recording, "final_accessibility_tree")
        if accessibility_path is not None and accessibility_path.exists():
            evidence.accessibility_trees[label] = _read_json(accessibility_path)
        action_metadata_path = _artifact_path(recording, "action_metadata")
        if action_metadata_path is not None:
            evidence.action_metadata.extend(read_jsonl(action_metadata_path))
        step_actions_path = _artifact_path(recording, "step_actions")
        if step_actions_path is not None:
            evidence.step_actions.extend(read_jsonl(step_actions_path))
        correlation_path = _artifact_path(recording, "business_event_correlation_index")
        if correlation_path is not None and correlation_path.exists():
            payload = _read_json(correlation_path)
            if isinstance(payload, list):
                evidence.business_event_correlations.extend(item for item in payload if isinstance(item, dict))
            elif isinstance(payload, dict):
                evidence.business_event_correlations.append(payload)


def _artifact_path(recording: dict[str, Any], key: str) -> Path | None:
    value = recording.get(key)
    if not value:
        return None
    return Path(str(value))


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def _load_sandbox_streams(sandbox_dir: Path, evidence: AgentAbuseEvidence) -> None:
    candidates = [
        sandbox_dir / "api",
        sandbox_dir / "outbox",
        sandbox_dir / "identity",
        sandbox_dir / "social",
        sandbox_dir / "web_state",
        sandbox_dir / "ads",
        sandbox_dir / "platform",
        sandbox_dir / "records",
        sandbox_dir / "memory",
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
