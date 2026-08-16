#!/usr/bin/env python3
"""Validate, schedule, and render the AgentGuard implementation roadmap."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import fnmatch
import hashlib
import html
import json
import os
import re
import subprocess
import sys
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Sequence

from jsonschema import Draft202012Validator


SCHEMA_VERSION = "1.0.0"
NON_SCHEDULING_RELATIONS = {"non_blocking", "observed_sequence"}
GENERATED_FILENAMES = ("roadmap.normalized.json", "roadmap.md", "index.html")
STATUS_ORDER = {"in_progress": 0, "ready": 1, "not_ready": 2, "completed": 3}
TERMINAL_LIFECYCLES = {"completed", "not_applicable"}
CONTROL_PLANE_PATTERNS = (
    ".github/workflows/ci.yml",
    ".gitignore",
    "AGENTS.md",
    "apps/dashboard/e2e/roadmap-artifact.spec.ts",
    "apps/dashboard/package.json",
    "apps/dashboard/playwright.roadmap.config.ts",
    "docs/06_delivery/roadmap/**",
    "docs/README.md",
    "package.json",
    "scripts/roadmap-tools.py",
    "tests/test_roadmap_tools.py",
)


class RoadmapError(RuntimeError):
    """A user-facing roadmap contract error."""


def _canonical_json(value: Any, *, indent: int | None = None) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        indent=indent,
        separators=None if indent is not None else (",", ":"),
        sort_keys=True,
    )


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RoadmapError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise RoadmapError(f"{path}: top-level JSON value must be an object")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    _atomic_write_text(path, _canonical_json(value, indent=2) + "\n")


def _atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(content, encoding="utf-8", newline="\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _utc_now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


class Roadmap:
    def __init__(self, root: Path, output_dir: Path | None = None) -> None:
        self.root = root.resolve()
        self.roadmap_dir = self.root / "docs" / "06_delivery" / "roadmap"
        self.schema_dir = self.roadmap_dir / "schema"
        self.source_dir = self.roadmap_dir / "source"
        self.nodes_dir = self.source_dir / "nodes"
        self.edges_dir = self.source_dir / "edges"
        self.evidence_dir = self.source_dir / "evidence"
        self.decisions_dir = self.source_dir / "decisions"
        self.generated_dir = (
            output_dir.resolve()
            if output_dir is not None
            else self.roadmap_dir / "generated"
        )
        self.catalog: dict[str, Any] = {}
        self.nodes: list[dict[str, Any]] = []
        self.edges: list[dict[str, Any]] = []
        self.evidence: list[dict[str, Any]] = []
        self.decisions: list[dict[str, Any]] = []
        self.node_paths: dict[str, Path] = {}

    def _source_path_exists(self, relative_path: str) -> bool:
        """Resolve document refs in fixtures against the tool's checkout as fallback."""
        if (self.root / relative_path).is_file():
            return True
        tool_root = Path(__file__).resolve().parents[1]
        return tool_root != self.root and (tool_root / relative_path).is_file()

    def load(self) -> None:
        self.catalog = _load_json(self.source_dir / "roadmap.json")
        self.nodes = self._load_collection(self.nodes_dir, recursive=False)
        self.edges = self._load_collection(self.edges_dir, recursive=False)
        self.evidence = self._load_collection(self.evidence_dir, recursive=True)
        self.decisions = self._load_collection(self.decisions_dir, recursive=False)
        self.node_paths = {
            node["id"]: path
            for path in sorted(self.nodes_dir.glob("*.json"))
            for node in [_load_json(path)]
            if isinstance(node.get("id"), str)
        }

    @staticmethod
    def _load_collection(directory: Path, *, recursive: bool) -> list[dict[str, Any]]:
        if not directory.exists():
            return []
        pattern = "**/*.json" if recursive else "*.json"
        return [_load_json(path) for path in sorted(directory.glob(pattern))]

    def validate(self) -> None:
        self.load()
        errors: list[str] = []
        errors.extend(
            self._schema_errors(self.catalog, "roadmap.schema.json", "roadmap")
        )
        for node in self.nodes:
            errors.extend(
                self._schema_errors(node, "node.schema.json", f"node {node.get('id')}")
            )
        for edge in self.edges:
            errors.extend(
                self._schema_errors(edge, "edge.schema.json", f"edge {edge.get('id')}")
            )
        for item in self.evidence:
            errors.extend(
                self._schema_errors(
                    item, "evidence.schema.json", f"evidence {item.get('id')}"
                )
            )

        errors.extend(self._unique_id_errors(self.nodes, "node"))
        errors.extend(self._unique_id_errors(self.edges, "edge"))
        errors.extend(self._unique_id_errors(self.evidence, "evidence"))
        errors.extend(self._unique_id_errors(self.decisions, "decision"))
        node_map = {node.get("id"): node for node in self.nodes}
        evidence_map = {item.get("id"): item for item in self.evidence}
        decision_ids = {item.get("id") for item in self.decisions}
        surface_ids = {
            surface.get("id") for surface in self.catalog.get("exclusive_surfaces", [])
        }

        for node_id, path in self.node_paths.items():
            if path.stem != node_id:
                errors.append(
                    f"node {node_id}: filename must be {node_id}.json, found {path.name}"
                )

        for node in self.nodes:
            node_id = node.get("id")
            unknown_surfaces = sorted(
                set(node.get("change_surfaces", [])) - surface_ids
            )
            if unknown_surfaces:
                errors.append(
                    f"node {node_id}: unknown change surfaces: {', '.join(unknown_surfaces)}"
                )
            acceptance_parent = node.get("acceptance_parent")
            if node.get("kind") == "acceptance":
                if acceptance_parent not in node_map:
                    errors.append(
                        f"node {node_id}: missing acceptance parent {acceptance_parent}"
                    )
            elif acceptance_parent is not None:
                errors.append(
                    f"node {node_id}: only acceptance nodes may set acceptance_parent"
                )
            for source_ref in node.get("source_refs", []):
                relative_path = source_ref.get("path", "")
                if not self._source_path_exists(relative_path):
                    errors.append(
                        f"node {node_id}: source path does not exist: {relative_path}"
                    )
            referenced_evidence = node.get("evidence_refs", [])
            referenced_items: list[dict[str, Any]] = []
            for reference in referenced_evidence:
                evidence_path = self.source_dir / reference
                if not evidence_path.is_file():
                    errors.append(
                        f"node {node_id}: evidence reference does not exist: {reference}"
                    )
                    continue
                item = _load_json(evidence_path)
                referenced_items.append(item)
                if item.get("node_id") != node_id:
                    errors.append(
                        f"node {node_id}: evidence {item.get('id')} belongs to "
                        f"{item.get('node_id')}"
                    )
            if node.get("lifecycle") == "completed":
                commit_evidence = [
                    item
                    for item in referenced_items
                    if item.get("status") == "verified" and item.get("kind") == "commit"
                ]
                if not commit_evidence:
                    errors.append(
                        f"node {node_id}: completed lifecycle requires referenced, "
                        "verified commit evidence"
                    )
                elif (self.root / ".git").exists() and not any(
                    _git_is_ancestor(
                        self.root, str(item.get("ref")), self.catalog["baseline_ref"]
                    )
                    for item in commit_evidence
                ):
                    errors.append(
                        f"node {node_id}: no referenced completion commit is reachable "
                        f"from {self.catalog['baseline_ref']}"
                    )

        for item in self.evidence:
            if item.get("node_id") not in node_map:
                errors.append(
                    f"evidence {item.get('id')}: missing node reference {item.get('node_id')}"
                )
            if item.get("id") not in evidence_map:
                errors.append(f"evidence has invalid id: {item.get('id')}")

        for edge in self.edges:
            edge_id = edge.get("id")
            for endpoint in ("from", "to"):
                if edge.get(endpoint) not in node_map:
                    errors.append(
                        f"edge {edge_id}: missing node reference {edge.get(endpoint)}"
                    )
            decision_id = edge.get("decision_id")
            if decision_id and decision_id not in decision_ids:
                errors.append(
                    f"edge {edge_id}: missing decision reference {decision_id}"
                )
            for source_ref in edge.get("source_refs", []):
                relative_path = source_ref.get("path", "")
                if not self._source_path_exists(relative_path):
                    errors.append(
                        f"edge {edge_id}: source path does not exist: {relative_path}"
                    )

        for node in self.nodes:
            node_id = node.get("id")
            if node.get("kind") == "acceptance":
                parent = node.get("acceptance_parent")
                if not any(
                    edge.get("from") == node_id
                    and edge.get("to") == parent
                    and edge.get("constraint") == "exit"
                    and edge.get("blocking") == "hard"
                    for edge in self.edges
                ):
                    errors.append(
                        f"node {node_id}: acceptance item needs a hard exit edge to {parent}"
                    )
            if node.get("lifecycle") != "completed":
                continue
            for edge in self.edges:
                if (
                    edge.get("to") == node_id
                    and self._is_scheduling_edge(edge)
                    and node_map.get(edge.get("from"), {}).get("lifecycle")
                    != "completed"
                ):
                    errors.append(
                        f"node {node_id}: completed while prerequisite "
                        f"{edge.get('from')} is not completed ({edge.get('id')})"
                    )

        for decision in self.decisions:
            decision_id = decision.get("id", "<unknown>")
            for source_ref in decision.get("source_refs", []):
                relative_path = source_ref.get("path", "")
                if not self._source_path_exists(relative_path):
                    errors.append(
                        f"decision {decision_id}: source path does not exist: {relative_path}"
                    )

        try:
            self._topological_ranks()
        except RoadmapError as exc:
            errors.append(str(exc))
        if errors:
            raise RoadmapError("roadmap validation failed:\n- " + "\n- ".join(errors))

    def _schema_errors(
        self, value: dict[str, Any], schema_name: str, label: str
    ) -> list[str]:
        schema_path = self.schema_dir / schema_name
        if not schema_path.is_file():
            return [f"missing schema: {schema_path}"]
        schema = _load_json(schema_path)
        try:
            Draft202012Validator.check_schema(schema)
            validator = Draft202012Validator(
                schema,
                registry=self._schema_registry(),
                format_checker=Draft202012Validator.FORMAT_CHECKER,
            )
            failures = sorted(
                validator.iter_errors(value),
                key=lambda failure: tuple(str(part) for part in failure.absolute_path),
            )
        except Exception as exc:  # jsonschema can wrap reference failures deeply.
            return [f"{label}: schema validation error: {exc}"]
        return [
            f"{label} /{'/'.join(str(part) for part in failure.absolute_path)}: {failure.message}"
            for failure in failures
        ]

    def _schema_registry(self):  # type: ignore[no-untyped-def]
        from referencing import Registry, Resource

        registry = Registry()
        for path in sorted(self.schema_dir.glob("*.schema.json")):
            document = _load_json(path)
            resource = Resource.from_contents(document)
            registry = registry.with_resource(document.get("$id", path.name), resource)
            registry = registry.with_resource(path.name, resource)
        return registry

    @staticmethod
    def _unique_id_errors(items: Sequence[dict[str, Any]], label: str) -> list[str]:
        seen: set[str] = set()
        errors: list[str] = []
        for item in items:
            item_id = item.get("id")
            if not isinstance(item_id, str):
                continue
            if item_id in seen:
                errors.append(f"duplicate {label} id: {item_id}")
            seen.add(item_id)
        return errors

    @staticmethod
    def _is_scheduling_edge(edge: dict[str, Any]) -> bool:
        return (
            edge.get("blocking") == "hard"
            and edge.get("relation") not in NON_SCHEDULING_RELATIONS
            and edge.get("constraint") in {"start", "activate", "exit"}
        )

    def _topological_ranks(self) -> dict[str, int]:
        node_ids = {node["id"] for node in self.nodes}
        incoming_count = {node_id: 0 for node_id in node_ids}
        outgoing: dict[str, list[str]] = defaultdict(list)
        for edge in self.edges:
            if not self._is_scheduling_edge(edge):
                continue
            source, target = edge.get("from"), edge.get("to")
            if (
                not isinstance(source, str)
                or not isinstance(target, str)
                or source not in node_ids
                or target not in node_ids
            ):
                continue
            outgoing[source].append(target)
            incoming_count[target] += 1
        queue = deque(
            sorted(node_id for node_id, count in incoming_count.items() if count == 0)
        )
        ranks = {node_id: 0 for node_id in node_ids}
        visited = 0
        while queue:
            source = queue.popleft()
            visited += 1
            for target in sorted(outgoing[source]):
                ranks[target] = max(ranks[target], ranks[source] + 1)
                incoming_count[target] -= 1
                if incoming_count[target] == 0:
                    queue.append(target)
        if visited != len(node_ids):
            cyclic = sorted(
                node_id for node_id, count in incoming_count.items() if count > 0
            )
            raise RoadmapError(
                "hard dependency DAG contains a cycle involving: " + ", ".join(cyclic)
            )
        return ranks

    def _critical_path(self, ranks: dict[str, int]) -> list[str]:
        """Return one deterministic longest implementation path for highlighting."""
        visible = {
            node["id"] for node in self.nodes if node.get("kind") != "acceptance"
        }
        predecessors: dict[str, list[str]] = defaultdict(list)
        for edge in self.edges:
            if (
                self._is_scheduling_edge(edge)
                and edge.get("from") in visible
                and edge.get("to") in visible
            ):
                predecessors[edge["to"]].append(edge["from"])
        paths: dict[str, list[str]] = {}
        for node_id in sorted(visible, key=lambda item: (ranks[item], item)):
            candidates = [
                paths[item] for item in predecessors[node_id] if item in paths
            ]
            prefix = max(candidates, key=lambda item: (len(item), item), default=[])
            paths[node_id] = [*prefix, node_id]
        return max(paths.values(), key=lambda item: (len(item), item), default=[])

    def normalize(self) -> dict[str, Any]:
        self.validate()
        node_map = {node["id"]: node for node in self.nodes}
        incoming: dict[str, list[dict[str, Any]]] = defaultdict(list)
        outgoing: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for edge in self.edges:
            incoming[edge["to"]].append(edge)
            outgoing[edge["from"]].append(edge)

        active = [
            node
            for node in self.nodes
            if node.get("lifecycle") == "in_progress"
            and not node.get("blocked")
            and not node.get("hold")
        ]
        evidence_by_node: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in self.evidence:
            evidence_by_node[item["node_id"]].append(item)
        ranks = self._topological_ranks()
        normalized_nodes: list[dict[str, Any]] = []
        for node in self.nodes:
            node_id = node["id"]
            conflicts: list[dict[str, Any]] = []
            surfaces = set(node.get("change_surfaces", []))
            for active_node in active:
                if active_node["id"] == node_id:
                    continue
                overlap = sorted(surfaces & set(active_node.get("change_surfaces", [])))
                if overlap:
                    conflicts.append(
                        {"node_id": active_node["id"], "surfaces": overlap}
                    )

            blockers_by_constraint: dict[str, list[str]] = {
                "start": [],
                "activate": [],
                "exit": [],
            }
            for edge in incoming[node_id]:
                if not self._is_scheduling_edge(edge):
                    continue
                prerequisite = node_map[edge["from"]]
                if prerequisite.get("lifecycle") != "completed":
                    blockers_by_constraint[edge["constraint"]].append(edge["id"])
            if node.get("blocked"):
                blockers_by_constraint["start"].append("node:blocked")
                blockers_by_constraint["activate"].append("node:blocked")
                blockers_by_constraint["exit"].append("node:blocked")
            if node.get("hold"):
                blockers_by_constraint["start"].append("node:hold")
                blockers_by_constraint["activate"].append("node:hold")
                blockers_by_constraint["exit"].append("node:hold")

            lifecycle = node.get("lifecycle")
            eligible_lifecycle = (
                lifecycle == "not_started"
                and node.get("kind") == "task"
                and not node.get("deferred", False)
            )
            can_start = (
                eligible_lifecycle
                and not blockers_by_constraint["start"]
                and not conflicts
            )
            can_activate = (
                lifecycle in {"not_started", "in_progress"}
                and not blockers_by_constraint["start"]
                and not blockers_by_constraint["activate"]
                and not conflicts
            )
            can_exit = (
                lifecycle in {"not_started", "in_progress"}
                and not any(blockers_by_constraint.values())
                and not conflicts
            )
            verified_evidence = [
                item
                for item in evidence_by_node[node_id]
                if item.get("status") == "verified"
            ]
            evidence_gap = lifecycle == "in_progress" and not verified_evidence
            if lifecycle == "completed":
                effective_status = "completed"
            elif lifecycle == "in_progress":
                effective_status = "in_progress"
            elif can_start:
                effective_status = "ready"
            else:
                effective_status = "not_ready"

            blocker_details: list[dict[str, Any]] = []
            edge_map = {edge["id"]: edge for edge in incoming[node_id]}
            for constraint in ("start", "activate", "exit"):
                for blocker_id in blockers_by_constraint[constraint]:
                    edge = edge_map.get(blocker_id)
                    blocker_details.append(
                        {
                            "id": blocker_id,
                            "constraint": constraint,
                            "from": edge.get("from") if edge else None,
                            "rationale": (
                                edge.get("rationale")
                                if edge
                                else blocker_id.removeprefix("node:")
                            ),
                        }
                    )
            for conflict in conflicts:
                blocker_details.append(
                    {
                        "id": f"resource:{conflict['node_id']}",
                        "constraint": "start/activate/exit",
                        "from": conflict["node_id"],
                        "rationale": "exclusive surface conflict: "
                        + ", ".join(conflict["surfaces"]),
                    }
                )

            normalized = copy.deepcopy(node)
            normalized.update(
                {
                    "effective_status": effective_status,
                    "can_start": can_start,
                    "can_activate": can_activate,
                    "can_exit": can_exit,
                    "unmet_dependencies": sorted(blockers_by_constraint["start"]),
                    "activation_blockers": sorted(
                        set(
                            blockers_by_constraint["start"]
                            + blockers_by_constraint["activate"]
                        )
                    ),
                    "exit_blockers": sorted(
                        set(
                            blockers_by_constraint["start"]
                            + blockers_by_constraint["activate"]
                            + blockers_by_constraint["exit"]
                        )
                    ),
                    "blocked_reasons": blocker_details,
                    "resource_conflicts": conflicts,
                    "evidence_gap": evidence_gap,
                    "evidence_items": sorted(
                        evidence_by_node[node_id], key=lambda item: item["id"]
                    ),
                    "topological_rank": ranks[node_id],
                    "incoming_edges": sorted(edge["id"] for edge in incoming[node_id]),
                    "outgoing_edges": sorted(edge["id"] for edge in outgoing[node_id]),
                }
            )
            normalized_nodes.append(normalized)

        lane_order = {
            lane["id"]: lane["order"] for lane in self.catalog.get("lanes", [])
        }
        normalized_nodes.sort(
            key=lambda node: (
                lane_order.get(node["lane"], 999),
                node["topological_rank"],
                STATUS_ORDER[node["effective_status"]],
                node["id"],
            )
        )
        ready_queue = [
            node["id"]
            for node in sorted(
                (
                    item
                    for item in normalized_nodes
                    if item["effective_status"] == "ready"
                ),
                key=lambda item: (
                    item["topological_rank"],
                    lane_order.get(item["lane"], 999),
                    item["id"],
                ),
            )
        ]
        resource_conflicts: list[dict[str, Any]] = []
        for left_index, left in enumerate(active):
            for right in active[left_index + 1 :]:
                overlap = sorted(
                    set(left.get("change_surfaces", []))
                    & set(right.get("change_surfaces", []))
                )
                if overlap:
                    resource_conflicts.append(
                        {
                            "nodes": sorted([left["id"], right["id"]]),
                            "surfaces": overlap,
                        }
                    )

        digest_inputs = {
            "catalog": self.catalog,
            "nodes": sorted(self.nodes, key=lambda item: item["id"]),
            "edges": sorted(self.edges, key=lambda item: item["id"]),
            "evidence": sorted(self.evidence, key=lambda item: item["id"]),
            "decisions": sorted(self.decisions, key=lambda item: item.get("id", "")),
        }
        source_digest = hashlib.sha256(
            _canonical_json(digest_inputs).encode("utf-8")
        ).hexdigest()
        return {
            "schema_version": SCHEMA_VERSION,
            "source_digest": source_digest,
            "baseline_ref": self.catalog["baseline_ref"],
            "lanes": self.catalog["lanes"],
            "nodes": normalized_nodes,
            "edges": sorted(self.edges, key=lambda edge: edge["id"]),
            "ready_queue": ready_queue,
            "resource_conflicts": resource_conflicts,
            "critical_path": self._critical_path(ranks),
        }

    def render(self) -> dict[str, str]:
        normalized = self.normalize()
        return {
            "roadmap.normalized.json": _canonical_json(normalized, indent=2) + "\n",
            "roadmap.md": render_markdown(normalized, self.catalog),
            "index.html": render_html(normalized, self.catalog),
        }

    def build(self) -> None:
        rendered = self.render()
        self.generated_dir.mkdir(parents=True, exist_ok=True)
        for filename, content in rendered.items():
            _atomic_write_text(self.generated_dir / filename, content)

    def check(self) -> None:
        rendered = self.render()
        stale: list[str] = []
        for filename, expected in rendered.items():
            path = self.generated_dir / filename
            if not path.is_file() or path.read_text(encoding="utf-8") != expected:
                stale.append(filename)
        if stale:
            raise RoadmapError(
                "generated roadmap is stale or out of date: " + ", ".join(stale)
            )

    def mutate_node(self, node_id: str, expected_revision: int) -> dict[str, Any]:
        self.validate()
        path = self.node_paths.get(node_id)
        if path is None:
            raise RoadmapError(f"unknown node: {node_id}")
        node = _load_json(path)
        if node["revision"] != expected_revision:
            raise RoadmapError(
                f"node {node_id}: expected revision {expected_revision}, found {node['revision']}"
            )
        return node

    def save_node(self, node: dict[str, Any]) -> None:
        path = self.node_paths[node["id"]]
        original = path.read_text(encoding="utf-8")
        _write_json(path, node)
        try:
            self.build()
        except Exception:
            _atomic_write_text(path, original)
            raise


def _safe_mermaid_id(node_id: str) -> str:
    return "N_" + re.sub(r"[^A-Za-z0-9_]", "_", node_id)


def _mermaid_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', "'").replace("\n", " ")


def render_markdown(normalized: dict[str, Any], catalog: dict[str, Any]) -> str:
    nodes = normalized["nodes"]
    visible_nodes = [node for node in nodes if node["kind"] != "acceptance"]
    visible_ids = {node["id"] for node in visible_nodes}
    lines = [
        "# AgentGuard 全轨实施路线图",
        "",
        f"> Source digest: `{normalized['source_digest']}`",
        "",
        "状态：🟢 已完成 · 🟠 正在实施 · 🔵 可启动 · ⚪ 未实施且不可启动。",
        "",
        "```mermaid",
        "flowchart LR",
    ]
    for lane in catalog.get("lanes", []):
        lane_nodes = [node for node in visible_nodes if node["lane"] == lane["id"]]
        if not lane_nodes:
            continue
        lines.append(
            f'  subgraph L_{_safe_mermaid_id(lane["id"])}["{_mermaid_label(lane["label"])}"]'
        )
        for node in lane_nodes:
            node_ref = _safe_mermaid_id(node["id"])
            label = _mermaid_label(f"{node['id']} · {node['exact_title']}")
            kind = node["kind"]
            if kind == "gate":
                expression = f'{node_ref}{{"{label}"}}'
            elif kind == "stage":
                expression = f'{node_ref}{{{{"{label}"}}}}'
            elif kind == "baseline":
                expression = f'{node_ref}[["{label}"]]'
            elif kind == "final":
                expression = f'{node_ref}[["{label}"]]'
            else:
                expression = f'{node_ref}["{label}"]'
            lines.append(f"    {expression}")
        lines.append("  end")
    for edge in normalized["edges"]:
        if edge["from"] not in visible_ids or edge["to"] not in visible_ids:
            continue
        if edge["relation"] == "observed_sequence":
            continue
        left, right = _safe_mermaid_id(edge["from"]), _safe_mermaid_id(edge["to"])
        constraint = (
            f"🔒 {edge['constraint']}"
            if edge["constraint"] == "activate"
            else edge["constraint"]
        )
        label = _mermaid_label(f"{constraint} · {edge['relation']}")
        if (
            edge["relation"] in {"optional", "fallback", "non_blocking"}
            or edge["blocking"] == "none"
        ):
            lines.append(f'  {left} -. "{label}" .-> {right}')
        elif edge["constraint"] == "start" or edge["relation"] == "join":
            lines.append(f'  {left} == "{label}" ==> {right}')
        else:
            lines.append(f'  {left} -- "{label}" --> {right}')
    for status, class_name in (
        ("completed", "completed"),
        ("in_progress", "inProgress"),
        ("ready", "ready"),
        ("not_ready", "notReady"),
    ):
        ids = [
            _safe_mermaid_id(node["id"])
            for node in visible_nodes
            if node["effective_status"] == status
        ]
        if ids:
            lines.append(f"  class {','.join(ids)} {class_name}")
    lines.extend(
        [
            "  classDef completed fill:#1F9D63,color:#fff,stroke:#126540",
            "  classDef inProgress fill:#D99000,color:#111,stroke:#8a5900",
            "  classDef ready fill:#2774D8,color:#fff,stroke:#174985",
            "  classDef notReady fill:#7B8494,color:#fff,stroke:#4b515c",
            "```",
            "",
            "## Ready Queue",
            "",
        ]
    )
    if normalized["ready_queue"]:
        lines.extend(f"- `{node_id}`" for node_id in normalized["ready_queue"])
    else:
        lines.append("- 当前没有可启动节点。")
    lines.extend(
        [
            "",
            "## 完整节点表",
            "",
            "| ID | 轨道 | 类型 | 状态 | 可启动 | 标题 |",
            "|---|---|---|---|---:|---|",
        ]
    )
    for node in nodes:
        title = node["exact_title"].replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| `{node['id']}` | {node['lane']} | {node['kind']} | "
            f"{node['effective_status']} | {'是' if node['can_start'] else '否'} | {title} |"
        )
    observed = [
        edge for edge in normalized["edges"] if edge["relation"] == "observed_sequence"
    ]
    lines.extend(["", "## History Overlay", ""])
    if observed:
        lines.extend(
            f"- `{edge['from']}` → `{edge['to']}`：{edge['rationale']}"
            for edge in observed
        )
    else:
        lines.append("- 当前没有只由 Git 历史观察到的顺序边。")
    return "\n".join(lines) + "\n"


def _json_for_script(value: Any) -> str:
    return (
        _canonical_json(value)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )


def render_html(normalized: dict[str, Any], catalog: dict[str, Any]) -> str:
    data_json = _json_for_script(normalized)
    palette_json = _json_for_script(catalog.get("state_palette", {}))
    fallback_rows = "\n".join(
        "<tr>"
        f"<td><code>{html.escape(node['id'])}</code></td>"
        f"<td>{html.escape(node['lane'])}</td>"
        f"<td>{html.escape(node['kind'])}</td>"
        f"<td>{html.escape(node['effective_status'])}</td>"
        f"<td>{html.escape(node['exact_title'])}</td>"
        "</tr>"
        for node in normalized["nodes"]
    )
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>AgentGuard 全轨实施路线图</title>
  <style>
    :root {{ --bg:#f4f7fb; --panel:#fff; --ink:#172033; --muted:#667085; --line:#cbd5e1; --focus:#7c3aed; --danger:#d64545; }}
    @media (prefers-color-scheme: dark) {{ :root {{ --bg:#0b1020; --panel:#141b2d; --ink:#f3f6fb; --muted:#aab4c5; --line:#3b465b; --focus:#b69cff; --danger:#ff6b6b; }} }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; overflow-x:hidden; background:var(--bg); color:var(--ink); font:14px/1.45 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif; }}
    header {{ display:flex; gap:18px; align-items:center; justify-content:space-between; padding:16px 20px; border-bottom:1px solid var(--line); background:var(--panel); }}
    h1 {{ margin:0; font-size:20px; }}
    .digest {{ color:var(--muted); font:11px ui-monospace,monospace; }}
    .layout {{ display:grid; grid-template-columns:minmax(0,1fr) 310px; width:100%; max-width:100vw; min-height:calc(100vh - 66px); overflow:hidden; }}
    main {{ min-width:0; overflow:hidden; padding:14px; }}
    aside {{ border-left:1px solid var(--line); background:var(--panel); padding:14px; overflow:auto; }}
    .toolbar {{ display:flex; flex-wrap:wrap; gap:10px; align-items:center; margin-bottom:10px; }}
    input[type=search] {{ min-width:240px; flex:1; padding:8px 10px; border:1px solid var(--line); border-radius:6px; background:var(--panel); color:var(--ink); }}
    select {{ padding:7px 9px; border:1px solid var(--line); border-radius:6px; background:var(--panel); color:var(--ink); }}
    fieldset {{ display:flex; flex-wrap:wrap; gap:8px; margin:0; padding:6px 9px; border:1px solid var(--line); border-radius:6px; }}
    legend {{ color:var(--muted); padding:0 4px; }}
    label {{ white-space:nowrap; }}
    button {{ border:1px solid var(--line); border-radius:6px; padding:6px 9px; background:var(--panel); color:var(--ink); cursor:pointer; }}
    button:focus-visible, input:focus-visible, [tabindex]:focus-visible {{ outline:3px solid var(--focus); outline-offset:2px; }}
    .graph {{ height:72vh; min-height:580px; border:1px solid var(--line); background:var(--panel); overflow:auto; position:relative; }}
    .graph svg {{ position:absolute; inset:0 auto auto 0; display:block; width:auto; height:auto; min-width:100%; min-height:100%; touch-action:none; }}
    .edge {{ fill:none; stroke:var(--line); stroke-width:1.4; opacity:.72; marker-end:url(#roadmap-arrow); }}
    .edge[data-constraint=start] {{ stroke-width:3; opacity:.92; }}
    .edge[data-constraint=activate] {{ stroke-width:2; opacity:.86; }}
    .edge[data-constraint=exit] {{ stroke-width:1.2; opacity:.72; }}
    .edge[data-relation=join] {{ stroke-width:3.4; opacity:.96; }}
    .edge[data-relation=optional] {{ stroke-dasharray:8 6; }}
    .edge[data-relation=fallback] {{ stroke-dasharray:9 4 2 4; }}
    .edge[data-relation=non_blocking] {{ stroke-dasharray:2 6; }}
    .edge[data-relation=observed_sequence] {{ stroke-dasharray:2 5; opacity:.52; }}
    .edge-label {{ fill:var(--muted); font-size:9px; pointer-events:none; }}
    .lane-label {{ fill:var(--muted); font-size:12px; font-weight:700; }}
    .lane-line {{ stroke:var(--line); stroke-width:1; stroke-dasharray:3 6; }}
    .roadmap-node {{ cursor:pointer; }}
    .roadmap-node .shape {{ stroke-width:2; }}
    .roadmap-node[data-status=completed] .shape {{ fill:#1F9D63; stroke:#126540; }}
    .roadmap-node[data-status=in_progress] .shape {{ fill:#D99000; stroke:#8a5900; }}
    .roadmap-node[data-status=ready] .shape {{ fill:#2774D8; stroke:#174985; }}
    .roadmap-node[data-status=not_ready] .shape {{ fill:#7B8494; stroke:#4b515c; }}
    .roadmap-node[data-blocked=true] .shape {{ stroke:var(--danger); stroke-width:4; }}
    .roadmap-node[data-optional=true] .shape {{ stroke-dasharray:7 4; }}
    .roadmap-node[data-evidence-gap=true] .evidence-gap {{ display:block; }}
    .roadmap-node .evidence-gap {{ display:none; }}
    .critical-mode .roadmap-node[data-critical=false], .critical-mode .edge[data-critical=false], .critical-mode .edge-label[data-critical=false] {{ opacity:.12; }}
    .critical-mode .roadmap-node[data-critical=true] .shape {{ stroke:var(--focus); stroke-width:4; }}
    .node-id {{ fill:white; font-size:11px; font-weight:800; pointer-events:none; }}
    .node-title {{ fill:white; font-size:10px; pointer-events:none; }}
    .ready-list {{ display:grid; gap:6px; }}
    .ready-list button {{ text-align:left; border-left:5px solid #2774D8; }}
    .conflict {{ border-left:5px solid var(--danger); padding:7px 9px; margin:8px 0; background:color-mix(in srgb,var(--danger) 10%,var(--panel)); }}
    .drawer {{ position:fixed; inset:0 0 0 auto; width:min(460px,92vw); background:var(--panel); border-left:1px solid var(--line); box-shadow:-10px 0 30px #0003; padding:18px; overflow:auto; z-index:20; }}
    .drawer[hidden] {{ display:none; }}
    .drawer header {{ padding:0 0 12px; border:0; }}
    .drawer dl {{ display:grid; grid-template-columns:130px 1fr; gap:7px; }}
    .drawer dt {{ color:var(--muted); }} .drawer dd {{ margin:0; overflow-wrap:anywhere; }}
    .badge {{ display:inline-block; border:1px solid var(--line); border-radius:999px; padding:2px 7px; margin:2px; }}
    .sr-only {{ position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; border:0; }}
    .fallback {{ padding:18px; background:var(--panel); }}
    .fallback table {{ border-collapse:collapse; width:100%; }} .fallback th,.fallback td {{ border:1px solid var(--line); padding:6px; text-align:left; }}
    @media (max-width:980px) {{ .layout {{ grid-template-columns:1fr; }} aside {{ border-left:0; border-top:1px solid var(--line); }} .graph {{ min-height:520px; }} }}
  </style>
</head>
<body>
  <header><div><h1>AgentGuard 全轨实施路线图</h1><div>依赖、门禁、并行与 Git 证据控制面</div></div><div class="digest">{html.escape(normalized["source_digest"][:16])}</div></header>
  <div class="layout">
    <main>
      <div class="toolbar">
        <label class="sr-only" for="roadmap-search">搜索节点</label>
        <input id="roadmap-search" data-testid="roadmap-search" type="search" placeholder="搜索 ID、标题或泳道…">
        <label>泳道 <select data-testid="lane-filter" id="lane-filter"><option value="">全部</option></select></label>
        <label>类型 <select data-testid="kind-filter" id="kind-filter"><option value="">全部</option></select></label>
        <fieldset><legend>状态</legend>
          <label><input data-testid="status-filter-completed" type="checkbox" data-status-filter="completed" checked> 已完成</label>
          <label><input type="checkbox" data-status-filter="in_progress" checked> 正在实施</label>
          <label><input type="checkbox" data-status-filter="ready" checked> 可启动</label>
          <label><input type="checkbox" data-status-filter="not_ready" checked> 未实施</label>
        </fieldset>
        <label><input data-testid="critical-path-toggle" id="critical-path-toggle" type="checkbox"> 突出关键路径</label>
        <label><input data-testid="history-overlay-toggle" id="history-overlay-toggle" type="checkbox"> History Overlay</label>
        <button type="button" data-testid="zoom-in" aria-label="放大">＋</button>
        <button type="button" data-testid="zoom-out" aria-label="缩小">−</button>
        <button type="button" data-testid="zoom-reset">重置</button>
      </div>
      <div class="graph" data-testid="roadmap-graph" aria-label="AgentGuard implementation dependency graph"><svg role="img" aria-labelledby="graph-title"><title id="graph-title">AgentGuard 实施依赖图</title><g></g></svg></div>
    </main>
    <aside>
      <h2>Ready Queue</h2>
      <div class="ready-list" data-testid="ready-queue"></div>
      <h2>共享表面冲突</h2>
      <div id="resource-conflicts"></div>
      <h2>图例</h2>
      <div id="legend"></div>
    </aside>
  </div>
  <section class="drawer" data-testid="node-drawer" hidden aria-label="节点详情" aria-live="polite">
    <header><h2 id="drawer-title"></h2><button type="button" data-testid="drawer-close" aria-label="关闭详情">关闭</button></header>
    <div id="drawer-body"></div>
  </section>
  <noscript><section class="fallback"><h2>完整节点表</h2><table><thead><tr><th>ID</th><th>泳道</th><th>类型</th><th>状态</th><th>标题</th></tr></thead><tbody>{fallback_rows}</tbody></table></section></noscript>
  <script id="roadmap-data" type="application/json">{data_json}</script>
  <script id="roadmap-palette" type="application/json">{palette_json}</script>
  <script>
  (() => {{
    'use strict';
    const data = JSON.parse(document.getElementById('roadmap-data').textContent);
    const palette = JSON.parse(document.getElementById('roadmap-palette').textContent);
    const svg = document.querySelector('[data-testid="roadmap-graph"] svg');
    const viewport = svg.querySelector('g');
    const graph = document.querySelector('[data-testid="roadmap-graph"]');
    const drawer = document.querySelector('[data-testid="node-drawer"]');
    const nodeMap = new Map(data.nodes.map(node => [node.id, node]));
    const graphNodes = data.nodes.filter(node => node.kind !== 'acceptance');
    const graphIds = new Set(graphNodes.map(node => node.id));
    const criticalIds = new Set(data.critical_path || []);
    const criticalPairs = new Set((data.critical_path || []).slice(1).map((id,index)=>`${{data.critical_path[index]}}→${{id}}`));
    const positions = new Map();
    let scale = 1, panX = 20, panY = 20, dragging = false, dragStart = null;
    const NS = 'http://www.w3.org/2000/svg';
    const make = (name, attrs={{}}) => {{ const element=document.createElementNS(NS,name); Object.entries(attrs).forEach(([key,value])=>element.setAttribute(key,String(value))); return element; }};
    const esc = value => String(value ?? '').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#39;');
    const defs=make('defs');
    const marker=make('marker',{{id:'roadmap-arrow',viewBox:'0 0 10 10',refX:9,refY:5,markerWidth:6,markerHeight:6,orient:'auto-start-reverse'}});
    marker.appendChild(make('path',{{d:'M 0 0 L 10 5 L 0 10 z',fill:'var(--line)'}}));defs.appendChild(marker);svg.prepend(defs);
    const groups = new Map();
    for (const node of graphNodes) {{
      const key = `${{node.lane}}:${{node.topological_rank}}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(node);
    }}
    let maxX=1200, maxY=800;
    const graphLanes = data.lanes.filter(lane => graphNodes.some(node => node.lane === lane.id));
    const laneBase = new Map();
    const maxRank = Math.max(...graphNodes.map(node => node.topological_rank));
    let laneCursor=90;
    for (const lane of graphLanes) {{
      const laneGroups=[...groups.entries()].filter(([key])=>key.startsWith(`${{lane.id}}:`)).map(([,items])=>items.length);
      const maxPeers=Math.max(1,...laneGroups);
      const baseY=laneCursor;laneBase.set(lane.id,baseY);
      laneCursor+=Math.max(170,90+(maxPeers-1)*82);
      const line=make('line',{{x1:165,y1:baseY-42,x2:Math.max(2700,(maxRank+2)*245),y2:baseY-42,class:'lane-line'}});
      viewport.appendChild(line);
      const label=make('text',{{x:12,y:baseY-17,class:'lane-label'}}); label.textContent=lane.label; viewport.appendChild(label);
    }}
    for (const node of graphNodes) {{
      const peers = groups.get(`${{node.lane}}:${{node.topological_rank}}`).sort((a,b)=>a.id.localeCompare(b.id));
      const slot=peers.findIndex(item=>item.id===node.id);
      const x=230+node.topological_rank*245;
      const y=laneBase.get(node.lane)+slot*82;
      positions.set(node.id,{{x,y}}); maxX=Math.max(maxX,x+210); maxY=Math.max(maxY,y+80);
    }}
    for (const edge of data.edges) {{
      if(!graphIds.has(edge.from)||!graphIds.has(edge.to)) continue;
      const a=positions.get(edge.from), b=positions.get(edge.to); if(!a||!b) continue;
      const isCritical=criticalPairs.has(`${{edge.from}}→${{edge.to}}`);
      const path=make('path',{{d:`M ${{a.x+92}} ${{a.y}} C ${{a.x+145}} ${{a.y}}, ${{b.x-145}} ${{b.y}}, ${{b.x-92}} ${{b.y}}`,class:'edge','data-edge-id':edge.id,'data-blocking':edge.blocking,'data-relation':edge.relation,'data-constraint':edge.constraint,'data-critical':isCritical?'true':'false'}});
      viewport.appendChild(path);
      if((edge.blocking==='hard' && edge.constraint!=='none') || edge.relation==='non_blocking') {{ const label=make('text',{{x:(a.x+b.x)/2,y:(a.y+b.y)/2-4,class:'edge-label','data-edge-label':edge.id,'data-critical':isCritical?'true':'false'}}); label.textContent=edge.relation==='non_blocking'?'does not block':(edge.constraint==='activate'?'🔒 ':'')+edge.constraint; viewport.appendChild(label); }}
    }}
    const shapeFor = node => {{
      const set=make('g',{{class:'shape-set'}});
      const add=element=>{{set.appendChild(element);return set;}};
      if(node.kind==='gate') return add(make('polygon',{{points:'0,-35 92,0 0,35 -92,0',class:'shape'}}));
      if(node.kind==='stage') return add(make('polygon',{{points:'-74,-35 74,-35 94,0 74,35 -74,35 -94,0',class:'shape'}}));
      if(node.kind==='join') return add(make('circle',{{cx:0,cy:0,r:16,class:'shape'}}));
      if(node.kind==='final') {{set.appendChild(make('polygon',{{points:'-74,-36 74,-36 94,0 74,36 -74,36 -94,0',class:'shape'}}));set.appendChild(make('polygon',{{points:'-68,-29 68,-29 86,0 68,29 -68,29 -86,0',class:'shape inner-shape'}}));return set;}}
      if(node.kind==='baseline') {{set.appendChild(make('rect',{{x:-92,y:-35,width:184,height:70,rx:2,class:'shape'}}));set.appendChild(make('rect',{{x:-85,y:-28,width:170,height:56,rx:1,class:'shape inner-shape'}}));return set;}}
      if(node.kind==='acceptance') return add(make('polygon',{{points:'-92,-34 72,-34 92,-14 92,34 -92,34',class:'shape'}}));
      return add(make('rect',{{x:-92,y:-35,width:184,height:70,rx:12,class:'shape'}}));
    }};
    for (const node of graphNodes) {{
      const pos=positions.get(node.id), group=make('g',{{transform:`translate(${{pos.x}},${{pos.y}})`,class:'roadmap-node',tabindex:'0',role:'button','aria-label':`${{node.id}} ${{node.exact_title}} ${{node.effective_status}}`,'data-node-id':node.id,'data-status':node.effective_status,'data-kind':node.kind,'data-lane':node.lane,'data-blocked':node.blocked?'true':'false','data-optional':node.optional?'true':'false','data-evidence-gap':node.evidence_gap?'true':'false','data-critical':criticalIds.has(node.id)?'true':'false'}});
      group.appendChild(shapeFor(node));
      const id=make('text',{{x:0,y:-7,'text-anchor':'middle',class:'node-id'}}); id.textContent=(palette[node.effective_status]?.icon||'')+' '+node.id; group.appendChild(id);
      const title=make('text',{{x:0,y:12,'text-anchor':'middle',class:'node-title'}}); title.textContent=node.exact_title.length>27?node.exact_title.slice(0,25)+'…':node.exact_title; group.appendChild(title);
      if((node.activation_blockers||[]).length && node.effective_status==='ready') {{ const lock=make('text',{{x:78,y:-20,'text-anchor':'middle',class:'node-id'}}); lock.textContent='🔒'; group.appendChild(lock); }}
      if(node.evidence_gap) {{ const warning=make('text',{{x:-78,y:-20,'text-anchor':'middle',class:'node-id evidence-gap'}}); warning.textContent='⚠'; group.appendChild(warning); }}
      group.addEventListener('click',()=>openNode(node.id));
      group.addEventListener('keydown',event=>{{if(event.key==='Enter'||event.key===' '){{event.preventDefault();openNode(node.id);}}}});
      viewport.appendChild(group);
    }}
    function applyTransform() {{ viewport.setAttribute('transform',`translate(${{panX}} ${{panY}}) scale(${{scale}})`);svg.setAttribute('width',String(Math.ceil(maxX*scale+40)));svg.setAttribute('height',String(Math.ceil(maxY*scale+40))); }}
    function resetZoom() {{ scale=1;panX=20;panY=20;graph.scrollTo({{left:0,top:0}});applyTransform(); }}
    applyTransform();
    document.querySelector('[data-testid="zoom-in"]').addEventListener('click',()=>{{scale=Math.min(2.5,scale*1.2);applyTransform();}});
    document.querySelector('[data-testid="zoom-out"]').addEventListener('click',()=>{{scale=Math.max(.12,scale/1.2);applyTransform();}});
    document.querySelector('[data-testid="zoom-reset"]').addEventListener('click',resetZoom);
    svg.addEventListener('pointerdown',event=>{{if(event.target.closest('.roadmap-node'))return;dragging=true;dragStart={{x:event.clientX-panX,y:event.clientY-panY}};svg.setPointerCapture(event.pointerId);}});
    svg.addEventListener('pointermove',event=>{{if(!dragging)return;panX=event.clientX-dragStart.x;panY=event.clientY-dragStart.y;applyTransform();}});
    svg.addEventListener('pointerup',()=>{{dragging=false;}});
    const filters=[...document.querySelectorAll('[data-status-filter]')];
    const laneFilter=document.getElementById('lane-filter'), kindFilter=document.getElementById('kind-filter');
    for(const lane of graphLanes){{const option=document.createElement('option');option.value=lane.id;option.textContent=lane.label;laneFilter.appendChild(option);}}
    for(const kind of [...new Set(graphNodes.map(node=>node.kind))].sort()){{const option=document.createElement('option');option.value=kind;option.textContent=kind;kindFilter.appendChild(option);}}
    function applyFilters() {{
      const query=document.querySelector('[data-testid="roadmap-search"]').value.trim().toLowerCase();
      const enabled=new Set(filters.filter(input=>input.checked).map(input=>input.dataset.statusFilter));
      const visible=new Set();
      for(const node of graphNodes){{const element=document.querySelector(`[data-node-id="${{CSS.escape(node.id)}}"]`);const match=(!query||`${{node.id}} ${{node.exact_title}} ${{node.lane}}`.toLowerCase().includes(query))&&(!laneFilter.value||node.lane===laneFilter.value)&&(!kindFilter.value||node.kind===kindFilter.value)&&enabled.has(node.effective_status);element.style.display=match?'':'none';if(match)visible.add(node.id);}}
      const history=document.getElementById('history-overlay-toggle').checked;
      for(const edge of data.edges){{const element=document.querySelector(`[data-edge-id="${{CSS.escape(edge.id)}}"]`);if(!element)continue;const show=visible.has(edge.from)&&visible.has(edge.to)&&(edge.relation!=='observed_sequence'||history);element.style.display=show?'':'none';const label=document.querySelector(`[data-edge-label="${{CSS.escape(edge.id)}}"]`);if(label)label.style.display=show?'':'none';}}
      graph.classList.toggle('critical-mode',document.getElementById('critical-path-toggle').checked);
    }}
    document.querySelector('[data-testid="roadmap-search"]').addEventListener('input',applyFilters); filters.forEach(input=>input.addEventListener('change',applyFilters));laneFilter.addEventListener('change',applyFilters);kindFilter.addEventListener('change',applyFilters);document.getElementById('critical-path-toggle').addEventListener('change',applyFilters);document.getElementById('history-overlay-toggle').addEventListener('change',applyFilters);
    const ready=document.querySelector('[data-testid="ready-queue"]');
    for(const id of data.ready_queue){{const node=nodeMap.get(id),button=document.createElement('button');button.type='button';button.dataset.nodeRef=id;button.textContent=`${{id}} · ${{node.exact_title}}`;button.addEventListener('click',()=>openNode(id));ready.appendChild(button);}}
    const conflicts=document.getElementById('resource-conflicts');
    if(!data.resource_conflicts.length) conflicts.textContent='当前没有共享表面冲突。';
    for(const conflict of data.resource_conflicts){{const item=document.createElement('div');item.className='conflict';item.textContent=`${{conflict.nodes.join(' ↔ ')}}：${{conflict.surfaces.join(', ')}}`;conflicts.appendChild(item);}}
    const legend=document.getElementById('legend');
    for(const [status,info] of Object.entries(palette)){{const item=document.createElement('div');item.className='badge';item.textContent=`${{info.icon}} ${{info.label}}`;item.style.borderLeft=`8px solid ${{info.color}}`;legend.appendChild(item);}}
    function openNode(id,updateHash=true){{
      const node=nodeMap.get(id);if(!node)return;
      document.getElementById('drawer-title').textContent=`${{node.id}} · ${{node.exact_title}}`;
      const sources=(node.source_refs||[]).map(ref=>`${{esc(ref.path)}}:${{esc(ref.line_hint)}} · ${{esc(ref.heading)}}`).join('<br>');
      const acceptance=data.edges.filter(edge=>edge.to===id&&nodeMap.get(edge.from)?.kind==='acceptance').map(edge=>nodeMap.get(edge.from));
      const blockers=(node.blocked_reasons||[]).map(item=>`${{esc(item.constraint)}} · ${{esc(item.from||item.id)}}：${{esc(item.rationale)}}`).join('<br>')||'无';
      const evidence=(node.evidence_items||[]).map(item=>`${{esc(item.status)}} · ${{esc(item.kind)}} · ${{esc(item.ref)}}<br>${{esc(item.summary)}}`).join('<hr>')||'无';
      const activationNote=node.can_start&&(node.activation_blockers||[]).length?'可开发，但不可 activation/完成':'—';
      document.getElementById('drawer-body').innerHTML=`<dl><dt>状态</dt><dd>${{esc(node.effective_status)}}${{node.evidence_gap?' · ⚠ evidence gap':''}}</dd><dt>泳道/类型</dt><dd>${{esc(node.lane)}} / ${{esc(node.kind)}}</dd><dt>可启动</dt><dd>${{node.can_start?'是':'否'}}</dd><dt>启用边界</dt><dd>${{activationNote}}</dd><dt>阻塞解释</dt><dd>${{blockers}}</dd><dt>Start blockers</dt><dd>${{esc((node.unmet_dependencies||[]).join(', ')||'无')}}</dd><dt>Activation blockers</dt><dd>${{esc((node.activation_blockers||[]).join(', ')||'无')}}</dd><dt>Exit blockers</dt><dd>${{esc((node.exit_blockers||[]).join(', ')||'无')}}</dd><dt>资源冲突</dt><dd>${{esc((node.resource_conflicts||[]).map(x=>x.node_id+': '+x.surfaces.join('/')).join(', ')||'无')}}</dd><dt>入边</dt><dd>${{esc((node.incoming_edges||[]).join(', ')||'无')}}</dd><dt>出边</dt><dd>${{esc((node.outgoing_edges||[]).join(', ')||'无')}}</dd><dt>Owner / 分支</dt><dd>${{esc(node.work?.owner||'—')}} / ${{esc(node.work?.branch||'—')}}</dd><dt>Worktree</dt><dd>${{esc(node.work?.worktree_slug||'—')}}</dd><dt>修改表面</dt><dd>${{esc((node.change_surfaces||[]).join(', ')||'无')}}</dd><dt>说明</dt><dd>${{esc((node.notes||[]).join('；')||'无')}}</dd><dt>来源</dt><dd>${{sources}}</dd><dt>证据</dt><dd>${{evidence}}</dd><dt>验收项</dt><dd id="drawer-acceptance">${{acceptance.length?acceptance.map(item=>`<button type="button" data-acceptance-ref="${{esc(item.id)}}">${{esc(item.id)}} · ${{esc(item.exact_title)}} · ${{esc(item.effective_status)}}</button>`).join(' '):'无'}}</dd></dl>`;
      drawer.querySelectorAll('[data-acceptance-ref]').forEach(button=>button.addEventListener('click',()=>openNode(button.dataset.acceptanceRef)));
      drawer.hidden=false;const pos=positions.get(id);if(pos)graph.scrollTo({{left:Math.max(0,pos.x*scale-graph.clientWidth/2),top:Math.max(0,pos.y*scale-graph.clientHeight/2),behavior:'smooth'}});if(updateHash)history.replaceState(null,'',`#node=${{encodeURIComponent(id)}}`);
    }}
    function closeDrawer(){{drawer.hidden=true;if(location.hash)history.replaceState(null,'',location.pathname+location.search);}}
    document.querySelector('[data-testid="drawer-close"]').addEventListener('click',closeDrawer);document.addEventListener('keydown',event=>{{if(event.key==='Escape')closeDrawer();}});
    function openHash(){{const match=location.hash.match(/^#node=(.+)$/);if(match)openNode(decodeURIComponent(match[1]),false);}} window.addEventListener('hashchange',openHash);openHash();applyFilters();
  }})();
  </script>
</body>
</html>
"""


def _print_json(value: Any) -> None:
    print(_canonical_json(value, indent=2))


def _find_node(normalized: dict[str, Any], node_id: str) -> dict[str, Any]:
    for node in normalized["nodes"]:
        if node["id"] == node_id:
            return node
    raise RoadmapError(f"unknown node: {node_id}")


def _git_is_ancestor(root: Path, commit: str, baseline: str) -> bool:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, baseline],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def _git_resolve_commit(root: Path, value: str) -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "--verify", f"{value}^{{commit}}"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _git_same_commit(root: Path, left: str, right: str) -> bool:
    resolved_left = _git_resolve_commit(root, left)
    resolved_right = _git_resolve_commit(root, right)
    if resolved_left is None or resolved_right is None:
        return left == right
    return resolved_left == resolved_right


def _git_show_json(root: Path, reference: str, path: str) -> dict[str, Any] | None:
    result = subprocess.run(
        ["git", "show", f"{reference}:{path}"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RoadmapError(f"{reference}:{path}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise RoadmapError(f"{reference}:{path}: expected a JSON object")
    return value


def _git_changed_paths(
    root: Path, base_ref: str, head_ref: str
) -> list[tuple[str, str]]:
    result = subprocess.run(
        ["git", "diff", "--name-status", "--find-renames", base_ref, head_ref],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RoadmapError(result.stderr.strip() or "git diff failed")
    changed: list[tuple[str, str]] = []
    for line in result.stdout.splitlines():
        if not line:
            continue
        fields = line.split("\t")
        status = fields[0]
        path = fields[-1]
        changed.append((status, path))
    return changed


def _matches_any(path: str, patterns: Sequence[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def _current_branch(root: Path) -> str:
    from_environment = os.environ.get("GITHUB_HEAD_REF")
    if from_environment:
        return from_environment
    result = subprocess.run(
        ["git", "branch", "--show-current"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _valid_lifecycle_transition(before: str, after: str) -> bool:
    if before == after:
        return True
    allowed = {
        "not_started": {"in_progress", "deferred", "not_applicable"},
        "in_progress": {"completed", "deferred"},
        "deferred": {"not_started", "in_progress", "not_applicable"},
        "completed": set(),
        "not_applicable": set(),
    }
    return after in allowed.get(before, set())


def _check_diff(roadmap: Roadmap, base_ref: str, head_ref: str) -> int:
    roadmap.validate()
    changes = _git_changed_paths(roadmap.root, base_ref, head_ref)
    changed_paths = {path for _, path in changes}
    generated_paths = {
        f"docs/06_delivery/roadmap/generated/{filename}"
        for filename in GENERATED_FILENAMES
    }
    changed_generated = changed_paths & generated_paths
    evidence_prefix = "docs/06_delivery/roadmap/source/evidence/"
    node_prefix = "docs/06_delivery/roadmap/source/nodes/"
    render_source_patterns = (
        "docs/06_delivery/roadmap/source/roadmap.json",
        "docs/06_delivery/roadmap/source/nodes/**",
        "docs/06_delivery/roadmap/source/edges/**",
        "docs/06_delivery/roadmap/source/decisions/**",
    )

    for status, path in changes:
        if path.startswith(evidence_prefix) and status != "A":
            raise RoadmapError(
                f"evidence is append-only; {path} has forbidden diff status {status}"
            )

    changed_node_paths = sorted(
        path
        for path in changed_paths
        if path.startswith(node_prefix) and path.endswith(".json")
    )
    for path in changed_node_paths:
        before = _git_show_json(roadmap.root, base_ref, path)
        after = _git_show_json(roadmap.root, head_ref, path)
        if after is None:
            raise RoadmapError(f"roadmap nodes cannot be deleted: {path}")
        if before is None:
            continue
        if after.get("revision") != before.get("revision", -1) + 1:
            raise RoadmapError(
                f"node {after.get('id')}: revision must increment exactly once "
                f"({before.get('revision')} -> {after.get('revision')})"
            )
        before_lifecycle = str(before.get("lifecycle"))
        after_lifecycle = str(after.get("lifecycle"))
        if not _valid_lifecycle_transition(before_lifecycle, after_lifecycle):
            raise RoadmapError(
                f"node {after.get('id')}: illegal lifecycle transition "
                f"{before_lifecycle} -> {after_lifecycle}"
            )
        if not set(before.get("evidence_refs", [])) <= set(
            after.get("evidence_refs", [])
        ):
            raise RoadmapError(
                f"node {after.get('id')}: evidence references are append-only"
            )

    referenced_evidence = {
        reference
        for node in roadmap.nodes
        for reference in node.get("evidence_refs", [])
    }
    referenced_evidence_paths = {
        f"docs/06_delivery/roadmap/source/{reference}"
        for reference in referenced_evidence
    }
    render_source_changed = any(
        _matches_any(path, render_source_patterns) for path in changed_paths
    ) or bool(changed_paths & referenced_evidence_paths)
    renderer_changed = "scripts/roadmap-tools.py" in changed_paths
    bootstrap = (
        _git_show_json(
            roadmap.root,
            base_ref,
            "docs/06_delivery/roadmap/source/roadmap.json",
        )
        is None
    )

    if render_source_changed:
        if changed_generated != generated_paths:
            missing = sorted(generated_paths - changed_generated)
            raise RoadmapError(
                "render-affecting roadmap source changed without all generated "
                f"artifacts: {', '.join(missing)}"
            )
        roadmap.check()
    elif renderer_changed or changed_generated:
        roadmap.check()
        if changed_generated and changed_generated != generated_paths:
            raise RoadmapError("generated roadmap artifacts must change as one set")
    elif not any(path.startswith(evidence_prefix) for path in changed_paths):
        roadmap.check()

    implementation_paths = sorted(
        path for path in changed_paths if not _matches_any(path, CONTROL_PLANE_PATTERNS)
    )
    added_evidence_nodes = {
        path[len(evidence_prefix) :].split("/", 1)[0]
        for status, path in changes
        if status == "A" and path.startswith(evidence_prefix)
    }
    if implementation_paths:
        branch = _current_branch(roadmap.root)
        push_context = os.environ.get("GITHUB_EVENT_NAME") == "push" or branch in {
            "dev",
            "main",
        }
        if push_context:
            candidates = [
                node
                for node in roadmap.nodes
                if node.get("id") in added_evidence_nodes
                and node.get("lifecycle") == "in_progress"
            ]
        else:
            candidates = [
                node
                for node in roadmap.nodes
                if node.get("lifecycle") == "in_progress"
                and (node.get("work") or {}).get("branch") == branch
            ]
        if len(candidates) != 1:
            raise RoadmapError(
                "implementation diff must map to exactly one active roadmap claim; "
                f"branch={branch or '<detached>'}, candidates="
                + ",".join(str(node.get("id")) for node in candidates)
            )
        claim = candidates[0]
        if claim["id"] not in added_evidence_nodes:
            raise RoadmapError(
                f"implementation diff for {claim['id']} must append node evidence"
            )
        forbidden_control_changes = sorted(
            path
            for path in changed_paths
            if _matches_any(path, CONTROL_PLANE_PATTERNS)
            and not path.startswith(f"{evidence_prefix}{claim['id']}/")
        )
        if forbidden_control_changes:
            raise RoadmapError(
                "feature worktree may only append its own evidence; forbidden paths: "
                + ", ".join(forbidden_control_changes)
            )
        surface_map = {
            surface["id"]: surface.get("path_patterns", [])
            for surface in roadmap.catalog.get("exclusive_surfaces", [])
        }
        allowed_patterns = [
            pattern
            for surface_id in claim.get("change_surfaces", [])
            for pattern in surface_map.get(surface_id, [])
        ]
        outside = [
            path
            for path in implementation_paths
            if not _matches_any(path, allowed_patterns)
        ]
        if outside:
            raise RoadmapError(
                f"claim {claim['id']} does not own changed paths: " + ", ".join(outside)
            )

    if bootstrap and not generated_paths <= changed_paths:
        raise RoadmapError("roadmap bootstrap must commit every generated artifact")
    return len(changes)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--output-dir", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate")
    commands.add_parser("build")
    commands.add_parser("check")
    ready = commands.add_parser("ready")
    ready.add_argument("--json", action="store_true")
    explain = commands.add_parser("explain")
    explain.add_argument("node")
    explain.add_argument("--json", action="store_true")
    claim = commands.add_parser("claim")
    claim.add_argument("node")
    claim.add_argument("--branch", required=True)
    claim.add_argument("--owner", required=True)
    claim.add_argument("--worktree-slug", required=True)
    claim.add_argument("--base-sha", required=True)
    claim.add_argument("--started-at")
    claim.add_argument("--expected-revision", required=True, type=int)
    evidence = commands.add_parser("add-evidence")
    evidence.add_argument("node")
    evidence.add_argument(
        "--kind", required=True, choices=["commit", "test", "ci", "doc", "worktree"]
    )
    evidence.add_argument("--ref", required=True)
    evidence.add_argument("--summary", required=True)
    evidence.add_argument(
        "--status", choices=["verified", "pending"], default="pending"
    )
    evidence.add_argument("--recorded-at")
    close = commands.add_parser("close")
    close.add_argument("node")
    close.add_argument("--commit", required=True)
    close.add_argument("--expected-revision", required=True, type=int)
    block = commands.add_parser("block")
    block.add_argument("node")
    block.add_argument("--reason", required=True)
    block.add_argument("--expected-revision", required=True, type=int)
    resume = commands.add_parser("resume")
    resume.add_argument("node")
    resume.add_argument("--expected-revision", required=True, type=int)
    diff = commands.add_parser("check-diff")
    diff.add_argument("--base-ref", required=True)
    diff.add_argument("--head-ref", default="HEAD")
    return parser


def run(args: argparse.Namespace) -> None:
    roadmap = Roadmap(args.root, args.output_dir)
    if args.command == "validate":
        roadmap.validate()
        print(f"validated {len(roadmap.nodes)} nodes and {len(roadmap.edges)} edges")
    elif args.command == "build":
        roadmap.build()
        print(f"built roadmap in {roadmap.generated_dir}")
    elif args.command == "check":
        roadmap.check()
        print("generated roadmap is current")
    elif args.command == "ready":
        normalized = roadmap.normalize()
        nodes = [
            {
                "id": node["id"],
                "exact_title": node["exact_title"],
                "lane": node["lane"],
                "effective_status": node["effective_status"],
                "activation_blockers": node["activation_blockers"],
                "exit_blockers": node["exit_blockers"],
            }
            for node in normalized["nodes"]
            if node["effective_status"] == "ready"
        ]
        if args.json:
            _print_json({"nodes": nodes})
        else:
            for node in nodes:
                print(f"{node['id']}\t{node['lane']}\t{node['exact_title']}")
    elif args.command == "explain":
        node = _find_node(roadmap.normalize(), args.node)
        if args.json:
            _print_json(node)
        else:
            print(f"{node['id']} · {node['exact_title']}")
            print(f"status: {node['effective_status']}")
            print(f"can_start: {node['can_start']}")
            print(
                "start blockers: " + (", ".join(node["unmet_dependencies"]) or "none")
            )
            print(
                "activation blockers: "
                + (", ".join(node["activation_blockers"]) or "none")
            )
            print("exit blockers: " + (", ".join(node["exit_blockers"]) or "none"))
    elif args.command == "claim":
        normalized = roadmap.normalize()
        effective = _find_node(normalized, args.node)
        if effective["effective_status"] != "ready":
            raise RoadmapError(f"node {args.node} is not ready")
        node = roadmap.mutate_node(args.node, args.expected_revision)
        node["lifecycle"] = "in_progress"
        node["revision"] += 1
        node["work"] = {
            "branch": args.branch,
            "worktree_slug": args.worktree_slug,
            "owner": args.owner,
            "base_sha": args.base_sha,
            "started_at": args.started_at or _utc_now(),
            "substate": "active",
        }
        roadmap.save_node(node)
        print(f"claimed {args.node} at revision {node['revision']}")
    elif args.command == "add-evidence":
        roadmap.validate()
        if args.node not in roadmap.node_paths:
            raise RoadmapError(f"unknown node: {args.node}")
        source_node = _load_json(roadmap.node_paths[args.node])
        if source_node.get("lifecycle") in TERMINAL_LIFECYCLES:
            raise RoadmapError(
                f"node {args.node} is terminal; completion evidence is immutable"
            )
        seed = f"{args.node}\0{args.kind}\0{args.ref}\0{args.summary}"
        suffix = hashlib.sha256(seed.encode()).hexdigest()[:12].upper()
        evidence_id = f"EV-{args.node}-{suffix}"
        path = roadmap.evidence_dir / args.node / f"{evidence_id}.json"
        if path.exists():
            raise RoadmapError(f"evidence already exists: {path}")
        _write_json(
            path,
            {
                "schema_version": SCHEMA_VERSION,
                "id": evidence_id,
                "node_id": args.node,
                "kind": args.kind,
                "ref": args.ref,
                "status": args.status,
                "summary": args.summary,
                "recorded_at": args.recorded_at or _utc_now(),
                "metadata": {},
            },
        )
        print(f"added {evidence_id}; integration owner must reference it during close")
    elif args.command == "close":
        normalized = roadmap.normalize()
        effective = _find_node(normalized, args.node)
        if effective["lifecycle"] in TERMINAL_LIFECYCLES:
            raise RoadmapError(f"node {args.node} is already terminal")
        if effective["kind"] == "task":
            if effective["lifecycle"] != "in_progress" or not effective.get("work"):
                raise RoadmapError(
                    f"task {args.node} must be claimed and in_progress before close"
                )
        elif effective["lifecycle"] not in {"not_started", "in_progress"}:
            raise RoadmapError(
                f"node {args.node} cannot close from {effective['lifecycle']}"
            )
        if not effective["can_exit"]:
            reasons = "; ".join(
                f"{item['id']}: {item['rationale']}"
                for item in effective["blocked_reasons"]
            )
            raise RoadmapError(
                f"node {args.node} cannot exit; {reasons or 'exit conditions unmet'}"
            )
        baseline = roadmap.catalog["baseline_ref"]
        if (roadmap.root / ".git").exists() and not _git_is_ancestor(
            roadmap.root, args.commit, baseline
        ):
            raise RoadmapError(f"commit {args.commit} is not reachable from {baseline}")
        evidence_paths: dict[str, Path] = {}
        for path in sorted((roadmap.evidence_dir / args.node).glob("*.json")):
            evidence_paths[_load_json(path)["id"]] = path
        matching_evidence = [
            item
            for item in roadmap.evidence
            if item.get("node_id") == args.node
            and item.get("status") == "verified"
            and item.get("kind") == "commit"
            and _git_same_commit(roadmap.root, str(item.get("ref")), args.commit)
        ]
        if not matching_evidence:
            raise RoadmapError(
                f"node {args.node} needs verified commit evidence matching {args.commit}"
            )
        node = roadmap.mutate_node(args.node, args.expected_revision)
        evidence_refs = set(node.get("evidence_refs", []))
        for item in matching_evidence:
            evidence_path = evidence_paths[item["id"]]
            evidence_refs.add(str(evidence_path.relative_to(roadmap.source_dir)))
        node["evidence_refs"] = sorted(evidence_refs)
        node["lifecycle"] = "completed"
        node["revision"] += 1
        if node.get("work") is not None:
            work = node["work"]
            work["substate"] = "closed"
            work["completed_commit"] = args.commit
        roadmap.save_node(node)
        print(f"closed {args.node} at revision {node['revision']}")
    elif args.command == "block":
        node = roadmap.mutate_node(args.node, args.expected_revision)
        if node.get("lifecycle") in TERMINAL_LIFECYCLES:
            raise RoadmapError(f"cannot block terminal node {args.node}")
        if node.get("blocked"):
            raise RoadmapError(f"node {args.node} is already blocked")
        node["blocked"] = True
        node["revision"] += 1
        node.setdefault("notes", []).append(f"BLOCKED: {args.reason}")
        roadmap.save_node(node)
        print(f"blocked {args.node}")
    elif args.command == "resume":
        node = roadmap.mutate_node(args.node, args.expected_revision)
        if node.get("lifecycle") in TERMINAL_LIFECYCLES:
            raise RoadmapError(f"cannot resume terminal node {args.node}")
        if not node.get("blocked"):
            raise RoadmapError(f"node {args.node} is not blocked")
        node["blocked"] = False
        node["revision"] += 1
        roadmap.save_node(node)
        print(f"resumed {args.node}")
    elif args.command == "check-diff":
        changed_count = _check_diff(roadmap, args.base_ref, args.head_ref)
        print(f"validated roadmap diff with {changed_count} changed paths")
    else:  # pragma: no cover - argparse makes this unreachable.
        raise RoadmapError(f"unsupported command: {args.command}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        run(args)
    except RoadmapError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
