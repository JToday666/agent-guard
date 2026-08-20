#!/usr/bin/env python3
"""[已弃用] 本方案已弃用：不采纳、不维护、不投入运行。

原因：contracts+--case-id 子集在 runner 中只产生单臂 V0 variant，
无法生成 A0-A4 五臂 350 行矩阵，合并链路确定性失败。
如需分组故障隔离能力，请联系集成负责人评估 runner 侧子集矩阵模式。

Run the competition matrix as isolated per-attack-type group commands.

Each of the 7 attack types becomes one independent ``competition_runner``
invocation (5 arms x 10 cases, serial inside the group). A crashed or
failing group never affects the others; any group can be diagnosed and
re-run in isolation via ``--only``.

The runner core is untouched: groups use the existing contracts suite with
a ``--case-id`` subset. LLM credentials are inherited from the caller's
environment and are never written anywhere by this script.

Usage:
    uv run python scripts/competition-grouped-run.py run \
        --root /tmp/grouped-run \
        -- --llm-base-url https://... --llm-model qwen3.7-plus \
           --llm-api-key-env AGENTGUARD_LLM_API_KEY --max-retries 3
    uv run python scripts/competition-grouped-run.py run \
        --root /tmp/grouped-run --only tool_hijacking   # re-run one group
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DATASET_DIR = REPO_ROOT / "agentguard_langgraph_bench/bench/datasets/attack_cases"
RUNNER_MODULE = "agentguard_langgraph_bench.bench.competition_runner"
PROFILE_ID = "competition-langgraph-v2"
GROUP_SUITE = "contracts"  # contracts/demo allow --case-id subsets


def load_groups() -> dict[str, list[str]]:
    """Map attack_type -> ordered case ids, straight from the frozen JSONL."""
    groups: dict[str, list[str]] = {}
    for path in sorted(DATASET_DIR.glob("*.jsonl")):
        if path.name == "dataset_manifest.json":
            continue
        case_ids: list[str] = []
        attack_type = path.stem
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                attack_type = str(record.get("attack_type") or path.stem)
                case_ids.append(str(record["case_id"]))
        if case_ids:
            groups.setdefault(attack_type, []).extend(case_ids)
    return groups


def status_path(root: Path) -> Path:
    return root / "grouped-status.json"


def read_status(root: Path) -> dict:
    path = status_path(root)
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    return {"groups": {}}


def write_status(root: Path, status: dict) -> None:
    root.mkdir(parents=True, exist_ok=True)
    status_path(root).write_text(
        json.dumps(status, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def group_passed(group_dir: Path) -> bool:
    """A finished group has a result.json whose status is 'passed'."""
    result_path = group_dir / "result.json"
    if not result_path.exists():
        return False
    try:
        payload = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return payload.get("status") == "passed" and payload.get("exit_code") == 0


def run_group(
    *,
    root: Path,
    attack_type: str,
    case_ids: list[str],
    extra_args: list[str],
) -> int:
    group_dir = root / f"group-{attack_type}"
    log_path = root / f"group-{attack_type}.log"
    command = [
        sys.executable,
        "-m",
        RUNNER_MODULE,
        "run",
        "--profile",
        PROFILE_ID,
        "--suite",
        GROUP_SUITE,
        "--artifacts",
        str(group_dir),
    ]
    for case_id in case_ids:
        command.extend(["--case-id", case_id])
    command.extend(extra_args)

    print(f"\n=== group {attack_type}: {len(case_ids)} cases ===")
    print(f"artifacts: {group_dir}")
    print(f"log:       {log_path}")
    started = time.monotonic()
    with log_path.open("w", encoding="utf-8") as log:
        log.write("$ " + " ".join(command) + "\n\n")
        log.flush()
        try:
            proc = subprocess.run(
                command,
                cwd=REPO_ROOT,
                stdout=log,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
            )
            exit_code = proc.returncode
        except KeyboardInterrupt:
            exit_code = 130
    duration = round(time.monotonic() - started, 1)
    verdict = "PASSED" if exit_code == 0 else f"exit {exit_code}"
    print(f"=== group {attack_type}: {verdict} in {duration}s ===")
    if exit_code != 0:
        print(f"    tail of {log_path}:")
        try:
            tail = log_path.read_text(encoding="utf-8").splitlines()[-25:]
            for line in tail:
                print(f"    | {line}")
        except OSError:
            pass
    return exit_code


def cmd_run(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    groups = load_groups()
    if not groups:
        print(f"no attack case files found under {DATASET_DIR}", file=sys.stderr)
        return 2

    selected = sorted(groups)
    if args.only:
        wanted = {item.strip() for item in args.only.split(",") if item.strip()}
        unknown = wanted - set(groups)
        if unknown:
            print(f"unknown attack types: {sorted(unknown)}", file=sys.stderr)
            return 2
        selected = [name for name in selected if name in wanted]

    status = read_status(root)
    failures: list[str] = []
    for attack_type in selected:
        group_dir = root / f"group-{attack_type}"
        if group_passed(group_dir) and not args.force:
            print(f"=== group {attack_type}: already passed, skipping (--force to re-run) ===")
            status["groups"][attack_type] = {
                **status["groups"].get(attack_type, {}),
                "status": "passed",
                "skipped": True,
            }
            continue
        exit_code = run_group(
            root=root,
            attack_type=attack_type,
            case_ids=groups[attack_type],
            extra_args=args.extra,
        )
        status["groups"][attack_type] = {
            "status": "passed" if exit_code == 0 else "failed",
            "exit_code": exit_code,
            "case_count": len(groups[attack_type]),
            "artifacts": str(group_dir),
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
        write_status(root, status)
        if exit_code != 0:
            failures.append(attack_type)
            if args.stop_on_failure:
                print("stopping after first failing group (--stop-on-failure)")
                break

    print("\n=== summary ===")
    for attack_type in sorted(groups):
        entry = status["groups"].get(attack_type, {})
        print(f"  {attack_type:<20} {entry.get('status', 'not-run')}")
    if failures:
        print(
            "\nfailed groups can be re-run after diagnosis, e.g.:\n"
            f"  python scripts/competition-grouped-run.py run --root {root} "
            f"--only {failures[0]} --force"
        )
        return 1
    print(f"\nall groups passed; merge with:\n  python scripts/competition-grouped-merge.py {root}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser("run", help="run per-group competition commands")
    run_parser.add_argument("--root", required=True, help="output root directory")
    run_parser.add_argument(
        "--only",
        help="comma-separated attack types to (re)run, e.g. benign,tool_hijacking",
    )
    run_parser.add_argument("--force", action="store_true", help="re-run even if already passed")
    run_parser.add_argument(
        "--stop-on-failure", action="store_true", help="abort remaining groups on first failure"
    )
    run_parser.add_argument(
        "extra",
        nargs=argparse.REMAINDER,
        help="extra runner args after '--' (provider flags, --max-retries, ...)",
    )
    args = parser.parse_args()
    if args.extra and args.extra[0] == "--":
        args.extra = args.extra[1:]
    return cmd_run(args)


if __name__ == "__main__":
    raise SystemExit(main())
