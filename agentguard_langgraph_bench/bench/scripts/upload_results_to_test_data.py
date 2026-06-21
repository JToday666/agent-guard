#!/usr/bin/env python3
"""Upload AgentGuard LangGraph benchmark results to zhuzhu0607/test_data.

This script is intentionally standalone: it does not modify or import the
benchmark runner, and it only copies already-written result artifacts.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCRIPT_PATH = Path(__file__).resolve()
BENCH_ROOT = SCRIPT_PATH.parents[1]
PROJECT_ROOT = SCRIPT_PATH.parents[2]
AGENT_GUARD_ROOT = SCRIPT_PATH.parents[3]
DEFAULT_RESULTS_DIR = BENCH_ROOT / "results"
DEFAULT_REPO_URL = "https://github.com/zhuzhu0607/test_data.git"
DEFAULT_REPO_DIR = AGENT_GUARD_ROOT.parent / "test_data"
DEFAULT_DEST_SUBDIR = "agentguard_langgraph_bench"


class UploadError(RuntimeError):
    pass


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    results_dir = Path(args.results_dir).expanduser().resolve()
    repo_dir = Path(args.repo_dir).expanduser().resolve()
    _progress(f"Selecting benchmark run from {results_dir}")
    run_json = _select_run_json(results_dir, args.run_id)
    run_id = run_json.stem
    _progress(f"Selected {run_json.name}")

    _ensure_external_repo_dir(repo_dir)
    _progress(f"Preparing results repository at {repo_dir}")
    _ensure_results_repo(repo_dir, args.repo_url, args.branch)

    destination = _unique_destination(repo_dir / args.dest_subdir, run_id)
    destination.mkdir(parents=True, exist_ok=False)
    _progress(f"Copying run artifacts into {destination}")
    copied = _copy_run_bundle(results_dir, run_json, destination)
    manifest = {
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "source_results_dir": str(results_dir),
        "source_run_json": str(run_json),
        "run_id": destination.name,
        "destination_repo": "zhuzhu0607/test_data",
        "destination_subdir": args.dest_subdir,
        "copied": copied,
    }
    (destination / "upload_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    _progress(f"Wrote upload_manifest.json; copied {len(copied)} artifact entries")

    output: dict[str, Any] = {
        "destination": str(destination),
        "run_id": destination.name,
        "copied": copied,
        "committed": False,
        "pushed": False,
    }

    if not args.no_commit:
        rel_destination = destination.relative_to(repo_dir)
        _progress(f"Staging {rel_destination}")
        _git(repo_dir, "add", str(rel_destination))
        status = _git(repo_dir, "status", "--short", str(rel_destination)).stdout.strip()
        output["git_status"] = status
        if status:
            _progress("Creating git commit")
            _git(repo_dir, "commit", "-m", f"Add AgentGuard benchmark results {destination.name}")
            output["committed"] = True
            output["commit"] = _git(repo_dir, "rev-parse", "HEAD").stdout.strip()
            if not args.no_push:
                _progress("Pushing to GitHub; git progress follows")
                if args.branch:
                    _git_stream(repo_dir, "push", "--progress", "origin", args.branch)
                else:
                    _git_stream(repo_dir, "push", "--progress")
                output["pushed"] = True
                _progress("Push complete")
        else:
            _progress("No new git changes to commit")

    print(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Upload one AgentGuard benchmark run to zhuzhu0607/test_data.")
    parser.add_argument(
        "--results-dir",
        default=str(DEFAULT_RESULTS_DIR),
        help="AgentGuard LangGraph bench results directory.",
    )
    parser.add_argument(
        "--run-id",
        default="latest",
        help="Run id such as run_20260620T174313792168Z, or 'latest'.",
    )
    parser.add_argument(
        "--repo-dir",
        default=str(DEFAULT_REPO_DIR),
        help="Local checkout path for zhuzhu0607/test_data. It must be outside agent-guard.",
    )
    parser.add_argument("--repo-url", default=DEFAULT_REPO_URL, help="Git URL for zhuzhu0607/test_data.")
    parser.add_argument("--branch", default="", help="Optional branch to checkout and push.")
    parser.add_argument(
        "--dest-subdir",
        default=DEFAULT_DEST_SUBDIR,
        help="Directory inside test_data where per-run folders are stored.",
    )
    parser.add_argument("--no-commit", action="store_true", help="Only copy files; do not git commit or push.")
    parser.add_argument("--no-push", action="store_true", help="Commit locally but do not push.")
    return parser


def _select_run_json(results_dir: Path, run_id: str) -> Path:
    if run_id == "latest":
        runs = sorted(
            [*results_dir.glob("run_*/run_*.json"), *results_dir.glob("run_*.json")],
            key=lambda path: path.stat().st_mtime,
        )
        if not runs:
            raise UploadError(f"No run_*.json files found in {results_dir}")
        return runs[-1]
    normalized = run_id.removesuffix(".json")
    if not normalized.startswith("run_"):
        normalized = f"run_{normalized}"
    candidates = [
        results_dir / normalized / f"{normalized}.json",
        results_dir / f"{normalized}.json",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise UploadError(f"Run result not found: {candidates[0]}")


def _ensure_external_repo_dir(repo_dir: Path) -> None:
    if repo_dir == AGENT_GUARD_ROOT or AGENT_GUARD_ROOT in repo_dir.parents:
        raise UploadError("Refusing to use JToday666/agent-guard or its subdirectory as the upload target.")


def _ensure_results_repo(repo_dir: Path, repo_url: str, branch: str) -> None:
    if repo_dir.exists():
        if not (repo_dir / ".git").exists():
            raise UploadError(f"Upload target is not a Git checkout: {repo_dir}")
    else:
        repo_dir.parent.mkdir(parents=True, exist_ok=True)
        clone_args = ["clone", "--progress", repo_url, str(repo_dir)]
        if branch:
            clone_args = ["clone", "--progress", "--branch", branch, repo_url, str(repo_dir)]
        _progress("Cloning zhuzhu0607/test_data; git progress follows")
        _git_stream(repo_dir.parent, *clone_args)

    remote = _git(repo_dir, "remote", "get-url", "origin", check=False).stdout.strip()
    if not remote:
        raise UploadError(f"Upload target has no origin remote: {repo_dir}")
    if not _remote_matches(remote, repo_url):
        raise UploadError(f"Upload target origin is {remote!r}; expected {repo_url!r}.")
    if branch:
        _git(repo_dir, "checkout", branch)


def _copy_run_bundle(results_dir: Path, run_json: Path, destination: Path) -> list[str]:
    copied: list[str] = []
    stamp = run_json.stem.removeprefix("run_")
    run_dir = run_json.parent if run_json.parent.name == f"run_{stamp}" else results_dir
    for source in [
        run_json,
        run_dir / f"run_{stamp}.csv",
        run_dir / f"summary_{stamp}.json",
        run_dir / f"manifest_run_{stamp}.json",
    ]:
        if source.exists() and source.is_file():
            _progress(f"Copying {source.name}")
            shutil.copy2(source, destination / source.name)
            copied.append(source.name)

    case_ids = _case_ids_from_run(run_json)
    _progress(f"Copying case artifacts for {len(case_ids)} cases")
    for case_id in case_ids:
        case_dir = run_dir / "cases" / case_id
        if not case_dir.exists():
            case_dir = results_dir / "cases" / case_id
        if case_dir.exists() and case_dir.is_dir():
            target = destination / "cases" / case_id
            _progress(f"Copying cases/{case_id}")
            shutil.copytree(case_dir, target)
            copied.append(str(target.relative_to(destination)))

    summary_path = run_dir / f"summary_{stamp}.json"
    sandbox_artifact_dir = _sandbox_artifact_dir(summary_path, run_json)
    if sandbox_artifact_dir is not None and sandbox_artifact_dir.exists():
        target = destination / "sandbox_artifacts" / sandbox_artifact_dir.name
        target.parent.mkdir(parents=True, exist_ok=True)
        _progress(f"Copying sandbox artifact {sandbox_artifact_dir.name}")
        shutil.copytree(sandbox_artifact_dir, target)
        copied.append(str(target.relative_to(destination)))
    return copied


def _case_ids_from_run(run_json: Path) -> list[str]:
    rows = json.loads(run_json.read_text(encoding="utf-8"))
    case_ids = {str(row.get("case_id") or "") for row in rows if isinstance(row, dict) and row.get("case_id")}
    return sorted(case_ids)


def _sandbox_artifact_dir(summary_path: Path, run_json: Path) -> Path | None:
    rows = json.loads(run_json.read_text(encoding="utf-8"))
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        archive = row.get("sandbox_archive")
        if isinstance(archive, dict) and archive.get("artifact_dir"):
            return Path(archive["artifact_dir"])

    if not summary_path.exists():
        return None
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    archive = summary.get("sandbox_archive") if isinstance(summary, dict) else None
    if isinstance(archive, dict) and archive.get("artifact_dir"):
        return Path(archive["artifact_dir"])

    manifest = summary.get("run_manifest") if isinstance(summary, dict) else None
    if not isinstance(manifest, dict):
        return None
    archive = manifest.get("sandbox_archive")
    if isinstance(archive, dict) and archive.get("artifact_dir"):
        return Path(archive["artifact_dir"])
    return None


def _unique_destination(parent: Path, run_id: str) -> Path:
    candidate = parent / run_id
    if not candidate.exists():
        return candidate
    index = 2
    while True:
        candidate = parent / f"{run_id}_{index}"
        if not candidate.exists():
            return candidate
        index += 1


def _remote_matches(actual: str, expected: str) -> bool:
    def normalize(value: str) -> str:
        value = value.strip().removesuffix(".git").rstrip("/")
        return value.replace("git@github.com:", "https://github.com/")

    return normalize(actual) == normalize(expected)


def _git(cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        check=False,
        text=True,
        capture_output=True,
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise UploadError(f"git {' '.join(args)} failed: {detail}")
    return completed


def _git_stream(cwd: Path, *args: str) -> None:
    completed = subprocess.run(["git", *args], cwd=str(cwd), check=False)
    if completed.returncode != 0:
        raise UploadError(f"git {' '.join(args)} failed with exit code {completed.returncode}")


def _progress(message: str) -> None:
    print(f"[upload-results] {message}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
