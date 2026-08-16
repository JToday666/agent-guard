from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ROADMAP_TOOL = REPOSITORY_ROOT / "scripts" / "roadmap-tools.py"
ROADMAP_SOURCE = REPOSITORY_ROOT / "docs" / "06_delivery" / "roadmap"
GENERATED_FILENAMES = ("roadmap.normalized.json", "roadmap.md", "index.html")


@pytest.fixture
def roadmap_root(tmp_path: Path) -> Path:
    target = tmp_path / "docs" / "06_delivery" / "roadmap"
    shutil.copytree(ROADMAP_SOURCE, target)
    return tmp_path


def run_tool(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ROADMAP_TOOL), "--root", str(root), *arguments],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def assert_succeeds(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode == 0, (
        f"command failed with {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


def assert_validation_failure(
    result: subprocess.CompletedProcess[str], *expected_terms: str
) -> None:
    assert result.returncode == 1, (
        f"expected validation failure, got {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    diagnostic = f"{result.stdout}\n{result.stderr}".lower()
    assert any(term.lower() in diagnostic for term in expected_terms), diagnostic


def git(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )


def initialize_git_fixture(root: Path, branch: str = "codex/ct03r-test") -> None:
    assert git(root, "init", "-b", branch).returncode == 0
    assert git(root, "config", "user.name", "Roadmap Test").returncode == 0
    assert git(root, "config", "user.email", "roadmap@example.invalid").returncode == 0
    assert git(root, "remote", "add", "origin", str(REPOSITORY_ROOT)).returncode == 0
    assert (
        git(
            root,
            "fetch",
            "origin",
            "refs/remotes/origin/dev:refs/remotes/origin/dev",
        ).returncode
        == 0
    )
    assert git(root, "add", ".").returncode == 0
    assert git(root, "commit", "-m", "roadmap fixture").returncode == 0


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def machine_dir(root: Path) -> Path:
    return root / "docs" / "06_delivery" / "roadmap" / "source"


def generated_dir(root: Path) -> Path:
    return root / "docs" / "06_delivery" / "roadmap" / "generated"


def objects(directory: Path) -> Iterator[tuple[Path, dict[str, Any]]]:
    for path in sorted(directory.glob("*.json")):
        yield path, read_json(path)


def object_path(root: Path, collection: str, object_id: str) -> Path:
    directory = machine_dir(root) / collection
    for path, value in objects(directory):
        if value.get("id") == object_id:
            return path
    raise AssertionError(f"{object_id!r} was not found in {directory}")


def mutate_object(
    root: Path, collection: str, object_id: str, **changes: Any
) -> dict[str, Any]:
    path = object_path(root, collection, object_id)
    value = read_json(path)
    value.update(changes)
    write_json(path, value)
    return value


def build_normalized(root: Path) -> dict[str, Any]:
    result = run_tool(root, "build")
    assert_succeeds(result)
    return read_json(generated_dir(root) / "roadmap.normalized.json")


def normalized_nodes(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    nodes = document.get("nodes")
    assert isinstance(nodes, list)
    return {node["id"]: node for node in nodes}


def add_edge(
    root: Path,
    *,
    edge_id: str,
    source: str,
    target: str,
    relation: str = "hard_dependency",
    constraint: str = "start",
    blocking: str = "hard",
) -> None:
    edge_directory = machine_dir(root) / "edges"
    _, template = next(objects(edge_directory))
    edge = {
        **template,
        "id": edge_id,
        "from": source,
        "to": target,
        "relation": relation,
        "constraint": constraint,
        "blocking": blocking,
        "rationale": "Temporary contract-test edge.",
        "provenance": "documented_planned",
    }
    edge["decision_id"] = None
    write_json(edge_directory / f"{edge_id}.json", edge)


def test_canonical_nodes_cover_all_four_effective_states_and_ready_json(
    roadmap_root: Path,
) -> None:
    document = build_normalized(roadmap_root)
    nodes = normalized_nodes(document)

    for node_id in ("FE04", "S1", "R05P", "RSC-CT01", "I01", "G-A"):
        assert nodes[node_id]["effective_status"] == "completed"
    for node_id in ("R05", "RM-00", "CT05"):
        assert nodes[node_id]["effective_status"] == "in_progress"
    for node_id in ("FE06", "CT03R"):
        assert nodes[node_id]["effective_status"] == "ready"
        assert nodes[node_id]["can_start"] is True
    for node_id in ("C10", "RSC-CTPROV"):
        assert nodes[node_id]["effective_status"] == "not_ready"

    result = run_tool(roadmap_root, "ready", "--json")
    assert_succeeds(result)
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)
    ready_ids = {node["id"] for node in payload["nodes"]}
    assert {"FE06", "CT03R"} <= ready_ids
    assert {
        "FE04",
        "S1",
        "RSC-CT01",
        "I01",
        "G-A",
        "R05P",
        "R05",
        "RM-00",
        "CT05",
        "RSC-CTPROV",
        "C10",
    }.isdisjoint(ready_ids)


def test_ready_is_derived_and_cannot_be_written_into_machine_source(
    roadmap_root: Path,
) -> None:
    mutate_object(roadmap_root, "nodes", "CT03R", ready=True)

    result = run_tool(roadmap_root, "validate")

    assert_validation_failure(result, "ready", "additional", "unknown")


def test_satisfied_start_dependencies_still_report_resource_conflict(
    roadmap_root: Path,
) -> None:
    nodes = normalized_nodes(build_normalized(roadmap_root))
    core_v21_10 = nodes["C10"]

    assert core_v21_10["can_start"] is False
    assert core_v21_10["effective_status"] == "not_ready"
    assert core_v21_10["unmet_dependencies"] == []
    assert core_v21_10["resource_conflicts"]

    result = run_tool(roadmap_root, "explain", "C10", "--json")
    assert_succeeds(result)
    explanation = json.loads(result.stdout)
    assert explanation["id"] == "C10"
    assert explanation["can_start"] is False
    assert explanation["unmet_dependencies"] == []
    assert explanation["resource_conflicts"]


def test_active_exclusive_surface_conflict_removes_otherwise_ready_node(
    roadmap_root: Path,
) -> None:
    active = read_json(object_path(roadmap_root, "nodes", "I01"))
    active_surfaces = active["change_surfaces"]
    assert active_surfaces, "I01 must reserve at least one exclusive surface"
    mutate_object(
        roadmap_root,
        "nodes",
        "CT03R",
        change_surfaces=list(active_surfaces),
    )

    nodes = normalized_nodes(build_normalized(roadmap_root))
    candidate = nodes["CT03R"]
    assert candidate["effective_status"] == "not_ready"
    assert candidate["can_start"] is False
    assert candidate["resource_conflicts"]

    result = run_tool(roadmap_root, "ready", "--json")
    assert_succeeds(result)
    ready_ids = {node["id"] for node in json.loads(result.stdout)["nodes"]}
    assert "CT03R" not in ready_ids


def test_blocked_node_is_not_ready_even_when_dependencies_are_satisfied(
    roadmap_root: Path,
) -> None:
    mutate_object(roadmap_root, "nodes", "CT03R", blocked=True)

    node = normalized_nodes(build_normalized(roadmap_root))["CT03R"]

    assert node["effective_status"] == "not_ready"
    assert node["can_start"] is False
    assert node["activation_blockers"]


def test_blocked_active_claim_keeps_exclusive_surface_reserved(
    roadmap_root: Path,
) -> None:
    active = read_json(object_path(roadmap_root, "nodes", "I01"))
    mutate_object(roadmap_root, "nodes", "I01", blocked=True)
    mutate_object(
        roadmap_root,
        "nodes",
        "CT03R",
        change_surfaces=list(active["change_surfaces"]),
    )

    candidate = normalized_nodes(build_normalized(roadmap_root))["CT03R"]

    assert candidate["effective_status"] == "not_ready"
    assert candidate["can_start"] is False
    assert candidate["resource_conflicts"]


def test_optional_non_blocking_edge_does_not_remove_ready_node(
    roadmap_root: Path,
) -> None:
    add_edge(
        roadmap_root,
        edge_id="E-TEST-OPTIONAL-C10-CT03R",
        source="C10",
        target="CT03R",
        relation="optional",
        constraint="start",
        blocking="none",
    )

    node = normalized_nodes(build_normalized(roadmap_root))["CT03R"]

    assert node["effective_status"] == "ready"
    assert node["can_start"] is True


def test_hard_dependency_graph_rejects_cycles(roadmap_root: Path) -> None:
    add_edge(
        roadmap_root,
        edge_id="E-TEST-CYCLE-FE04-S1",
        source="FE04",
        target="S1",
    )
    add_edge(
        roadmap_root,
        edge_id="E-TEST-CYCLE-S1-FE04",
        source="S1",
        target="FE04",
    )

    result = run_tool(roadmap_root, "validate")

    assert_validation_failure(result, "cycle", "cyclic", "dag")


def test_edge_with_missing_node_reference_is_rejected(roadmap_root: Path) -> None:
    add_edge(
        roadmap_root,
        edge_id="E-TEST-MISSING-NODE",
        source="FE04",
        target="DOES-NOT-EXIST",
    )

    result = run_tool(roadmap_root, "validate")

    assert_validation_failure(result, "does-not-exist", "missing", "reference")


def test_completed_lifecycle_requires_verified_completion_evidence(
    roadmap_root: Path,
) -> None:
    mutate_object(
        roadmap_root,
        "nodes",
        "CT03R",
        lifecycle="completed",
        evidence_refs=[],
        work=None,
    )

    result = run_tool(roadmap_root, "validate")

    assert_validation_failure(result, "evidence", "verified", "completed")


def test_gate_exit_is_blocked_by_each_unfinished_atomic_acceptance(
    roadmap_root: Path,
) -> None:
    gate = normalized_nodes(build_normalized(roadmap_root))["G-B"]

    assert gate["can_exit"] is False
    acceptance_blockers = {
        item["from"]
        for item in gate["blocked_reasons"]
        if str(item.get("from", "")).startswith("A-GB-")
    }
    assert acceptance_blockers == {f"A-GB-{index:02d}" for index in range(1, 9)}


def test_append_only_evidence_is_referenced_atomically_when_task_closes(
    roadmap_root: Path,
) -> None:
    before_generated = {
        name: (generated_dir(roadmap_root) / name).read_bytes()
        for name in GENERATED_FILENAMES
    }
    claim = run_tool(
        roadmap_root,
        "claim",
        "CT03R",
        "--branch",
        "codex/ct03r-test",
        "--owner",
        "test-owner",
        "--worktree-slug",
        "ct03r-test",
        "--base-sha",
        "cdf3625",
        "--expected-revision",
        "0",
    )
    assert_succeeds(claim)
    after_claim_generated = {
        name: (generated_dir(roadmap_root) / name).read_bytes()
        for name in GENERATED_FILENAMES
    }
    assert after_claim_generated != before_generated

    for kind in ("commit", "test", "ci", "review", "rollback"):
        evidence = run_tool(
            roadmap_root,
            "add-evidence",
            "CT03R",
            "--kind",
            kind,
            "--ref",
            "deadbee" if kind == "commit" else f"proof:{kind}",
            "--summary",
            f"verified {kind} proof",
            "--status",
            "verified",
        )
        assert_succeeds(evidence)
    assert {
        name: (generated_dir(roadmap_root) / name).read_bytes()
        for name in GENERATED_FILENAMES
    } == after_claim_generated

    close = run_tool(
        roadmap_root,
        "close",
        "CT03R",
        "--commit",
        "deadbee",
        "--expected-revision",
        "1",
    )
    assert_succeeds(close)
    closed = read_json(object_path(roadmap_root, "nodes", "CT03R"))
    assert closed["lifecycle"] == "completed"
    assert closed["revision"] == 2
    assert any("evidence/CT03R/" in ref for ref in closed["evidence_refs"])
    assert_succeeds(run_tool(roadmap_root, "validate"))


def test_close_requires_complete_verified_exit_evidence_before_mutation(
    roadmap_root: Path,
) -> None:
    assert_succeeds(
        run_tool(
            roadmap_root,
            "claim",
            "CT03R",
            "--branch",
            "codex/ct03r-test",
            "--owner",
            "test-owner",
            "--worktree-slug",
            "ct03r-test",
            "--base-sha",
            "cdf3625",
            "--expected-revision",
            "0",
        )
    )
    assert_succeeds(
        run_tool(
            roadmap_root,
            "add-evidence",
            "CT03R",
            "--kind",
            "commit",
            "--ref",
            "deadbee",
            "--summary",
            "commit only is insufficient",
            "--status",
            "verified",
        )
    )
    before = read_json(object_path(roadmap_root, "nodes", "CT03R"))

    result = run_tool(
        roadmap_root,
        "close",
        "CT03R",
        "--commit",
        "deadbee",
        "--expected-revision",
        "1",
    )

    assert_validation_failure(result, "required", "ci", "review", "rollback", "test")
    assert read_json(object_path(roadmap_root, "nodes", "CT03R")) == before


def test_unreferenced_evidence_is_excluded_from_render_until_close(
    roadmap_root: Path,
) -> None:
    before = build_normalized(roadmap_root)
    assert_succeeds(
        run_tool(
            roadmap_root,
            "add-evidence",
            "CT03R",
            "--kind",
            "test",
            "--ref",
            "pytest:pending",
            "--summary",
            "pending feature-worktree proof",
        )
    )

    after = build_normalized(roadmap_root)

    assert after["source_digest"] == before["source_digest"]
    assert normalized_nodes(after)["CT03R"]["evidence_items"] == []


def test_evidence_only_diff_must_belong_to_current_branch_claim(
    roadmap_root: Path,
) -> None:
    mutate_object(
        roadmap_root,
        "nodes",
        "CT03R",
        lifecycle="in_progress",
        revision=1,
        work={
            "branch": "codex/ct03r-test",
            "worktree_slug": "ct03r-test",
            "owner": "test-owner",
            "base_sha": "cdf3625",
            "started_at": None,
            "substate": "active",
        },
    )
    initialize_git_fixture(roadmap_root)
    evidence_dir = machine_dir(roadmap_root) / "evidence" / "RSC-CT01"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        evidence_dir / "EV-RSC-CT01-WRONG-BRANCH.json",
        {
            "schema_version": "1.0.0",
            "id": "EV-RSC-CT01-WRONG-BRANCH",
            "node_id": "RSC-CT01",
            "kind": "test",
            "ref": "pytest:wrong-owner",
            "status": "pending",
            "summary": "must not be accepted from CT03R branch",
            "recorded_at": None,
            "metadata": {},
        },
    )
    assert git(roadmap_root, "add", ".").returncode == 0
    assert git(roadmap_root, "commit", "-m", "wrong evidence owner").returncode == 0

    result = run_tool(
        roadmap_root,
        "check-diff",
        "--base-ref",
        "HEAD^",
        "--head-ref",
        "HEAD",
    )

    assert_validation_failure(result, "evidence-only", "active roadmap claim")


def test_evidence_rename_cannot_evade_append_only_check(roadmap_root: Path) -> None:
    source = (
        machine_dir(roadmap_root) / "evidence" / "CT03R" / "EV-CT03R-UNREFERENCED.json"
    )
    source.parent.mkdir(parents=True, exist_ok=True)
    write_json(
        source,
        {
            "schema_version": "1.0.0",
            "id": "EV-CT03R-UNREFERENCED",
            "node_id": "CT03R",
            "kind": "test",
            "ref": "pytest:pending",
            "status": "pending",
            "summary": "unreferenced append-only proof",
            "recorded_at": None,
            "metadata": {},
        },
    )
    initialize_git_fixture(roadmap_root)
    destination = (
        machine_dir(roadmap_root)
        / "evidence"
        / "CT03R"
        / "archived"
        / "EV-CT03R-UNREFERENCED.json"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    assert git(roadmap_root, "mv", str(source), str(destination)).returncode == 0
    assert git(roadmap_root, "commit", "-m", "rename evidence").returncode == 0

    result = run_tool(
        roadmap_root,
        "check-diff",
        "--base-ref",
        "HEAD^",
        "--head-ref",
        "HEAD",
    )

    assert_validation_failure(result, "append-only", "forbidden diff status")


def test_close_rejects_unmet_start_exit_and_resource_blockers(
    roadmap_root: Path,
) -> None:
    before = read_json(object_path(roadmap_root, "nodes", "C10"))

    result = run_tool(
        roadmap_root,
        "close",
        "C10",
        "--commit",
        "deadbee",
        "--expected-revision",
        "0",
    )

    assert_validation_failure(result, "cannot exit", "resource", "r05")
    assert read_json(object_path(roadmap_root, "nodes", "C10")) == before


def test_build_is_deterministic_and_check_detects_stale_artifacts(
    roadmap_root: Path,
) -> None:
    build_normalized(roadmap_root)
    first = {
        name: (generated_dir(roadmap_root) / name).read_bytes()
        for name in GENERATED_FILENAMES
    }

    build_normalized(roadmap_root)
    second = {
        name: (generated_dir(roadmap_root) / name).read_bytes()
        for name in GENERATED_FILENAMES
    }
    assert second == first

    node_path = object_path(roadmap_root, "nodes", "CT03R")
    node = read_json(node_path)
    node["exact_title"] = f"{node['exact_title']} (stale-source-probe)"
    write_json(node_path, node)

    result = run_tool(roadmap_root, "check")

    assert_validation_failure(result, "stale", "out of date", "generated")


def test_html_generation_escapes_untrusted_machine_text(roadmap_root: Path) -> None:
    hostile = '<script>alert("roadmap-xss")</script><img src=x onerror=alert(1)>'
    mutate_object(roadmap_root, "nodes", "CT03R", exact_title=hostile)

    build_normalized(roadmap_root)
    html = (generated_dir(roadmap_root) / "index.html").read_text(encoding="utf-8")

    assert '<script>alert("roadmap-xss")</script>' not in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert any(
        escaped in html
        for escaped in (
            "&lt;script&gt;",
            "\\u003cscript\\u003e",
            "\\x3cscript\\x3e",
        )
    )
